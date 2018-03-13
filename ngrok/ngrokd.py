#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import asyncio
from ngrok.base_service import BaseService
from ngrok.config import CONFIG_FILE_PATH, DEFAULT_PEM_FILE, DEFAULT_KEY_FILE
from ngrok.handler.ngrok_handler import NgrokHandler

event_loop = asyncio.get_event_loop()

s = BaseService(event_loop, NgrokHandler, is_ssl=True, cert_file=CONFIG_FILE_PATH + DEFAULT_PEM_FILE, key_file=CONFIG_FILE_PATH + DEFAULT_KEY_FILE)

event_loop.set_debug(True)

event_loop.run_until_complete(s.start())