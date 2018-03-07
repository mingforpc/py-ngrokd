#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import ssl
import abc
import socket
import asyncio
from ngrok.logger import logger


DEFAULT_SERVER_DOMAIN = 'localhost.com'
DEFAULT_SERVER_HOST = '127.0.0.1'
DEFAULT_SERVER_HTTP = 28080
DEFAULT_SERVER_HTTPS = 24443
DEFAULT_SERVER_PORT = 14443



class BaseService(abc.ABC):

    def __init__(self, host, port, event_loop, ssl=False, hostname=None, cert_file=None, key_file=None, listen=100):
        self.host = host
        self.port = port
        self.event_loop = event_loop
        self.ssl = ssl
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
            if self.ssl and (self.cert_file is None or self.key_file is None):
                raise Exception("If you want to enable ssl, please set cert_file and key_file")

            if self.ssl:
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

        if self.running:
            return

        if not self.initialized:
            self.initialize()

        self.running = True

        while self.running:
            await self.handle_connect()

    async def handle_connect(self):
        conn, address = await  self.event_loop.sock_accept(self.__socket)


event_loop = asyncio.get_event_loop()

s = BaseService('0.0.0.0', 5000, event_loop)

event_loop.set_debug(True)
# task = event_loop.create_task(s.start)
event_loop.run_until_complete(s.start())