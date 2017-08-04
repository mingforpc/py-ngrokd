#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import logging.config

from src.ngrok import CONFIG_FILE_PATH

logging.config.fileConfig(CONFIG_FILE_PATH + 'logger.config')

logger = logging.getLogger('ngrok')