#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import ssl
import abc
import socket
import asyncio
from ngrok.logger import logger
from ngrok.util import tolen
from ngrok.config import CONFIG_FILE_PATH, DEFAULT_PEM_FILE, DEFAULT_KEY_FILE, DEFAULT_BUF_SIZE

DEFAULT_SERVER_DOMAIN = 'localhost.com'
DEFAULT_SERVER_HOST = '127.0.0.1'
DEFAULT_SERVER_HTTP = 28080
DEFAULT_SERVER_HTTPS = 24443
DEFAULT_SERVER_PORT = 14443


class BaseService(abc.ABC):

    def __init__(self, event_loop, handler_cls, host=None, port=None, is_ssl=False, hostname=None, cert_file=None, key_file=None, listen=100):
        self.host = host
        self.port = port
        self.event_loop = event_loop
        self.handler_cls = handler_cls
        self.is_ssl = is_ssl
        self.hostname = hostname
        self.cert_file = cert_file
        self.key_file = key_file
        self._listen = listen

        self.context = None
        self.__socket = None
        self.running = False

        self.initialized = False

    def initialize(self):

        if not self.initialized:
            if self.is_ssl and (self.cert_file is None or self.key_file is None):
                raise Exception("If you want to enable ssl, please set cert_file and key_file")

            if self.is_ssl:
                self.context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
                self.context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

            self.__socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.__socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT & socket.SO_REUSEADDR, 1)

            self.__socket.bind((self.host if self.host is not None else DEFAULT_SERVER_HOST,
                                self.port if self.port is not None else DEFAULT_SERVER_PORT))

            self.__socket.listen(self._listen)
            self.__socket.setblocking(0)
            self.initialized = True

    async def start(self):

        logger.debug("start to run")

        if self.running:
            return

        if not self.initialized:
            self.initialize()

        self.running = True

        while self.running:
            await self.handle_connect()

    async def handle_connect(self):
        conn, address = await self.event_loop.sock_accept(self.__socket)
        conn.setblocking(0)
        if self.is_ssl:
            conn = self.context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False,
                                            server_hostname=self.hostname)
            logger.debug("start ssl handshake")
            self._on_handshake(conn)
        else:
            self.event_loop.add_reader(conn.fileno(), self._on_read, conn)

    def _on_handshake(self, conn):
        """
        SSL handshake function, copy from asyncio.selector_events.
        :param conn: client connection socket
        :return:
        """
        try:
            conn.do_handshake()
        except ssl.SSLWantReadError:
            self.event_loop.add_reader(conn.fileno(), self._on_handshake, conn)
            return
        except ssl.SSLWantWriteError:
            self.event_loop.add_writer(conn.fileno(), self._on_handshake, conn)
            return
        except BaseException as exc:

            logger.warning("%r: SSL handshake failed", self, exc_info=True)
            self.event_loop.remove_reader(conn.fileno())
            self.event_loop.remove_writer(conn.fileno())
            conn.close()
            if isinstance(exc, Exception):
                return
            else:
                raise

        self.event_loop.remove_reader(conn.fileno())
        self.event_loop.remove_writer(conn.fileno())
        logger.debug("ssl handshake finish")

        handler = self.handler_cls(conn, self.event_loop)
        self.event_loop.add_reader(handler.fd, handler.read_handler)

    def _on_read(self, conn):
        """

        :param conn:
        :return:
        """
        try:
            data = conn.recv(8)
            content_len = tolen(data[0:8])
            data = conn.recv(content_len)
            buf = data.decode('utf-8')

            print(content_len)
            print(len(buf))
            print(buf)

            if data == '':
                self.event_loop.remove_reader(conn.fileno())
                conn.close()
        except ssl.SSLWantReadError as ex:
            pass


class NgrokHandler:

    def __init__(self, conn, loop):

        self.conn = conn
        self.loop = loop
        self.fd = conn.fileno()
        self.binary_data = None

    def read_handler(self):
        """
         处理read回调。
        :return:
        """
        try:
            data = self.conn.recv(120)
        except ssl.SSLWantReadError:
            return

        if not data:
            self.loop.remove_reader(self.conn.fileno())
            self.conn.close()
        else:
            request_size = tolen(data[:8])

            if request_size > len(data[8:]):
                # 请求没接收全，继续接受
                logger.debug(data[8:])

                self.binary_data = bytearray(data)

                # 移除旧的read回调
                self.loop.remove_reader(self.fd)
                # 因为请求未接受完, 使用继续接收的read回调
                self.loop.add_reader(self.fd, self.continue_read_handler)
            else:
                # 请求接受全
                logger.debug(data[8:])
                pass

    def continue_read_handler(self):
        """
        处理read回调。用来处理请求过大没有一次接收完的。
        :return:
        """
        try:
            data = self.conn.recv(120)

        except ssl.SSLWantReadError as ex:
            logger.debug("SSLWantReadError")
            return

        if not data:
            self.loop.remove_reader(self.conn.fileno())
            self.conn.close()
        else:
            logger.debug(111)
            request_size = tolen(self.binary_data[:8])
            print('request_size:' + str(request_size))
            try:
                self.binary_data = bytearray(bytes(self.binary_data) + data)
            except Exception as ex:
                logger.exception("test:", exc_info=ex)
            if request_size > len(self.binary_data[8:]):
                # 请求没接收全，继续接受
                print(self.binary_data[8:])
                # self.loop.add_reader(self.fd, self.continue_read_handler)
            elif request_size < len(self.binary_data[8:]):
                # 请求的大小，小于收到的大小，有TCP粘包

                # 获取本次请求
                request_data = self.binary_data[8: 8 + request_size]
                print(request_data)
                # TODO: 在这里要做处理请求

                # 移除已处理请求的数据
                self.binary_data = self.binary_data[8 + request_size:]

            else:
                # 请求接受全
                request_data = self.binary_data[8:]
                print(request_data)
                # TODO: 在这里要做处理请求

                self.binary_data = None

                # 移除继续读的read回调
                self.loop.remove_reader(self.fd)
                # 因为已经处理完大请求，改用回普通read回调
                self.loop.add_reader(self.fd, self.read_handler)







event_loop = asyncio.get_event_loop()

s = BaseService(event_loop, NgrokHandler, is_ssl=True, cert_file=CONFIG_FILE_PATH + DEFAULT_PEM_FILE, key_file=CONFIG_FILE_PATH + DEFAULT_KEY_FILE)

event_loop.set_debug(True)

# task = event_loop.create_task(s.start)
event_loop.run_until_complete(s.start())

from http .server import HTTPServer