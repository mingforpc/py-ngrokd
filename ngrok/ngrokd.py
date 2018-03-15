#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import asyncio
from ngrok.base_service import BaseService
from ngrok.config import CONFIG_FILE_PATH, DEFAULT_PEM_FILE, DEFAULT_KEY_FILE, DEFAULT_SERVER_HTTP, DEFAULT_SERVER_PORT
from ngrok.handler.ngrok_handler import NgrokHandler
from ngrok.handler.http_handler import HttpHandler

event_loop = asyncio.get_event_loop()

s = BaseService(event_loop, NgrokHandler, is_ssl=True, cert_file=CONFIG_FILE_PATH + DEFAULT_PEM_FILE,
                key_file=CONFIG_FILE_PATH + DEFAULT_KEY_FILE, port=DEFAULT_SERVER_PORT)

http = BaseService(event_loop, HttpHandler, port=DEFAULT_SERVER_HTTP)


event_loop.set_debug(True)
asyncio.ensure_future(http.start(), loop=event_loop)
asyncio.ensure_future(s.start(), loop=event_loop)


def exception_handler(ex):
    print(ex)

event_loop.set_exception_handler(exception_handler)


event_loop.run_forever()
