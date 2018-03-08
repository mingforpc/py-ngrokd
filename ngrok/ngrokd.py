#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import ssl
import abc
import socket
import struct
import asyncio
from ngrok.logger import logger
from ngrok.config import CONFIG_FILE_PATH, DEFAULT_PEM_FILE, DEFAULT_KEY_FILE

DEFAULT_SERVER_DOMAIN = 'localhost.com'
DEFAULT_SERVER_HOST = '127.0.0.1'
DEFAULT_SERVER_HTTP = 28080
DEFAULT_SERVER_HTTPS = 24443
DEFAULT_SERVER_PORT = 14443


class BaseService(abc.ABC):

    def __init__(self, event_loop, host=None, port=None, is_ssl=False, hostname=None, cert_file=None, key_file=None, listen=100):
        self.host = host
        self.port = port
        self.event_loop = event_loop
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

    @staticmethod
    def tolen(data):
        if len(data) == 8:
            return struct.unpack('<II', data)[0]
        return 0

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

        self.event_loop.add_reader(conn.fileno(), self._on_read, conn)

    def _on_read(self, conn):
        """

        :param conn:
        :return:
        """
        try:
            data = conn.recv(8)
            content_len = self.tolen(data[0:8])
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




event_loop = asyncio.get_event_loop()

s = BaseService(event_loop, is_ssl=True, cert_file=CONFIG_FILE_PATH + DEFAULT_PEM_FILE, key_file=CONFIG_FILE_PATH + DEFAULT_KEY_FILE)

event_loop.set_debug(True)

# task = event_loop.create_task(s.start)
event_loop.run_until_complete(s.start())

from http .server import HTTPServer