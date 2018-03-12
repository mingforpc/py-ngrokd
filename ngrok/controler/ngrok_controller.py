import time
from ngrok.config import DEFAULT_SERVER_DOMAIN, DEFAULT_SERVER_HTTP
from ngrok.util import md5, get_rand_char
from ngrok.logger import logger
from ngrok.err import get_err_msg
from ngrok.err import ERR_SUCCESS, ERR_FAILED


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
                url = 'https://' + domain_name + ':' + str(DEFAULT_SERVER_HTTP)
            else:
                url = protocol + '://' + domain_name

            return ERR_SUCCESS, get_err_msg(ERR_SUCCESS), url
        except Exception as ex:
            logger.exception("exception in process req_tunnel_http:", exc_info=ex)
            return ERR_FAILED, get_err_msg(ERR_FAILED), None

    # @staticmethod
    # def reg_proxy(client_id):
    #     """
    #     process RegProxy
    #     :param client_id:
    #     :return: (err, msg, linkinfo)
    #     """
    #     try:
    #         if client_id not in GLOBAL_CACHE.PROXY_SOCKET_LIST:
    #             return Err.ERR_UNREGISTERED_CLIENT_ID, Err.get_err_msg(Err.ERR_UNREGISTERED_CLIENT_ID), None
    #
    #         return Err.ERR_SUCCESS, Err.get_err_msg(Err.ERR_SUCCESS), None
    #     except Exception as ex:
    #         logger.exception("Exception in process reg_proxy:", exc_info=ex)
    #         return Err.ERR_FAILED, Err.get_err_msg(Err.ERR_FAILED), None

    # @classmethod
    # def req_tunnel_http(cls, req_id, protocol, hostname=None, subdomain=None, http_auth=None):
    #     """
    #     process ReqTunnel with http/https tunnel
    #     :param req_id:
    #     :param protocol:
    #     :param hostname:
    #     :param subdomain:
    #     :param http_auth:
    #     :return: (err, msg, url)
    #     """
    #     try:
    #         if hostname is not None and hostname.strip() != '':
    #             domain_name = hostname
    #         else:
    #             if subdomain is None or subdomain.strip() == '':
    #                 subdomain = getRandChar(5)
    #             domain_name = subdomain + '.' + DEFAULT_SERVER_DOMAIN
    #
    #         if protocol == 'http' and DEFAULT_SERVER_HTTP != 80:
    #             url = 'http://' + domain_name + ':' + str(DEFAULT_SERVER_HTTP)
    #         elif protocol == 'https' and DEFAULT_SERVER_HTTP != 443:
    #             url = 'https://' + domain_name + ':' + str(DEFAULT_SERVER_HTTP)
    #         else:
    #             url = protocol + '://' + domain_name
    #
    #         if url in GLOBAL_CACHE.HOSTS:
    #             return Err.ERR_URL_EXISTED, Err.get_err_msg(Err.ERR_URL_EXISTED), None
    #
    #         return Err.ERR_SUCCESS, Err.get_err_msg(Err.ERR_SUCCESS), url
    #     except Exception as ex:
    #         logger.exception("Exception in process req_tunnel_http:", exc_info=ex)
    #         return Err.ERR_FAILED, Err.get_err_msg(Err.ERR_FAILED), None

    # @classmethod
    # def req_tunnel_tcp(cls, req_tunnel):
    #     """
    #     process ReqTunnel with tcp tunnel
    #     :param req_tunnel:
    #     :return: (err, msg, (url, remote_port))
    #     """
    #     try:
    #         remote_port = req_tunnel['Payload']['RemotePort']
    #         url = req_tunnel['Payload']['Protocol'] + '://' + DEFAULT_SERVER_DOMAIN + ':' + str(remote_port)
    #         if url in GLOBAL_CACHE.TCPS:
    #             return Err.ERR_URL_EXISTED, Err.get_err_msg(Err.ERR_URL_EXISTED), None
    #
    #         return Err.ERR_SUCCESS, Err.get_err_msg(Err.ERR_SUCCESS), (url, remote_port)
    #     except Exception as ex:
    #         logger.exception("Exception in process req_tunnel_tcp:", exc_info=ex)
    #         return Err.ERR_FAILED, Err.get_err_msg(Err.ERR_FAILED), None

