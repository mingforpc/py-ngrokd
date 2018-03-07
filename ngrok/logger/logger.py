#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import logging.config

CONFIG_FILE_PATH = os.path.split(os.path.realpath(__file__))[0] + "/../"

logging.config.fileConfig(CONFIG_FILE_PATH + 'logger.config')

logger = logging.getLogger('ngrok')