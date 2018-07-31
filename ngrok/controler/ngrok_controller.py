#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import time
from ngrok.config import DEFAULT_SERVER_DOMAIN, DEFAULT_SERVER_HTTP, DEFAULT_SERVER_HTTPS
from ngrok.util import md5, get_rand_char
from ngrok.logger import logger
from ngrok.err import get_err_msg
from ngrok.err import ERR_SUCCESS, ERR_FAILED, ERR_CLIENT_ID_NOT_EXIST
from ngrok.global_cache import GLOBAL_CACHE


class NgrokController:
    @classmethod
    def auth(cls, user, password, version=None, mm_version=None, os_type=None, arch=None):
        """
        Process Auth
        :param user:
        :param password:
        :param version:
        :param mm_version: major/minor software version
        :param os_type:
        :param arch:
        :return: (err, msg, client_id)
        """
        try:

            # user = auth_req['Payload'].get('User')
            # pwd = auth_req['Payload'].get('Password')

            # err, msg, result = UserController.login(user, '', pwd)

            # if err != Err.ERR_SUCCESS:
            #     return err, msg, result

            now = time.time()
            client_id = md5(str(now))
            return ERR_SUCCESS, get_err_msg(ERR_SUCCESS), client_id
        except Exception as ex:
            logger.exception("Exception in process auth:", exc_info=ex)
            return ERR_FAILED, get_err_msg(ERR_FAILED), None

    @staticmethod
    def req_tunnel_http(req_id, protocol, hostname=None, subdomain=None, http_auth=None):
        """
        process ReqTunnel with http/https tunnel
        :param req_id:
        :param protocol:
        :param hostname:
        :param subdomain:
        :param http_auth:
        :return: (err, msg, url)
        """

        try:
            if hostname is not None and hostname.strip() != '':
                domain_name = hostname
            else:
                if subdomain is None or subdomain.strip() == '':
                    subdomain = get_rand_char(5)
                domain_name = subdomain + '.' + DEFAULT_SERVER_DOMAIN

            if protocol == 'http' and DEFAULT_SERVER_HTTP != 80:
                url = 'http://' + domain_name + ':' + str(DEFAULT_SERVER_HTTP)
            elif protocol == 'https' and DEFAULT_SERVER_HTTP != 443:
                url = 'https://' + domain_name + ':' + str(DEFAULT_SERVER_HTTPS)
            else:
                url = protocol + '://' + domain_name

            return ERR_SUCCESS, get_err_msg(ERR_SUCCESS), url
        except Exception as ex:
            logger.exception("exception in process req_tunnel_http:", exc_info=ex)
            return ERR_FAILED, get_err_msg(ERR_FAILED), None

    @staticmethod
    def reg_proxy(client_id):
        """
        判断这个client_id是否已经登录的client_id
        :param client_id:
        :return:
        """
        try:
            if client_id not in GLOBAL_CACHE.TUNNEL_LIST:
                return ERR_CLIENT_ID_NOT_EXIST, get_err_msg(ERR_CLIENT_ID_NOT_EXIST), None
            else:
                return ERR_SUCCESS, get_err_msg(ERR_SUCCESS), None
        except Exception as ex:
            logger.exception("exception in process reg_proxy:", exc_info=ex)
            return ERR_FAILED, get_err_msg(ERR_FAILED), None