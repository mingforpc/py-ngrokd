#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import ssl
import abc
import socket
from ngrok.logger import logger
from ngrok.config import DEFAULT_SERVER_HOST


class BaseService(abc.ABC):

    def __init__(self, loop, handler_cls, host=None, port=None, is_ssl=False, hostname=None, cert_file=None, key_file=None, listen=100):
        self.host = host
        self.port = port
        self.loop = loop
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

            self.__socket.bind((self.host if self.host is not None else DEFAULT_SERVER_HOST, self.port))

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
        conn, address = await self.loop.sock_accept(self.__socket)
        conn.setblocking(0)
        if self.is_ssl:
            conn = self.context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False,
                                            server_hostname=self.hostname)
            logger.debug("start ssl handshake")
            self._on_handshake(conn)
        else:
            handler = self.handler_cls(conn, self.loop)
            self.loop.add_reader(handler.fd, handler.read_handler)

    def _on_handshake(self, conn):
        """
        SSL handshake function, copy from asyncio.selector_events.
        :param conn: client connection socket
        :return:
        """
        try:
            conn.do_handshake()
        except ssl.SSLWantReadError:
            self.loop.add_reader(conn.fileno(), self._on_handshake, conn)
            return
        except ssl.SSLWantWriteError:
            self.loop.add_writer(conn.fileno(), self._on_handshake, conn)
            return
        except BaseException as exc:

            logger.warning("%r: SSL handshake failed", self, exc_info=True)
            self.loop.remove_reader(conn.fileno())
            self.loop.remove_writer(conn.fileno())
            conn.close()
            if isinstance(exc, Exception):
                return
            else:
                raise

        self.loop.remove_reader(conn.fileno())
        self.loop.remove_writer(conn.fileno())
        logger.debug("ssl handshake finish")

        handler = self.handler_cls(conn, self.loop)
        self.loop.add_reader(handler.fd, handler.read_handler)