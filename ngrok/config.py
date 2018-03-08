#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os

CONFIG_FILE_PATH = os.path.split(os.path.realpath(__file__))[0] + "/../"

DEFAULT_SERVER_DOMAIN = 'localhost.com'
DEFAULT_SERVER_HOST = '127.0.0.1'
DEFAULT_SERVER_HTTP = 28080
DEFAULT_SERVER_HTTPS = 24443
DEFAULT_SERVER_PORT = 14443

DEFAULT_PEM_FILE = 'snakeoil.crt'
DEFAULT_KEY_FILE = 'snakeoil.key'

DEFAULT_BUF_SIZE = 1024*8
