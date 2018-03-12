#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import ssl
import abc
import json
import socket
import asyncio
from ngrok.err import ERR_SUCCESS, ERR_UNKNOWN_REQUEST, ERR_UNREGISTERED_CLIENT_ID, ERR_UNSUPPORTED_PROTOCOL, \
    ERR_URL_EXISTED, get_err_msg
from ngrok.logger import logger
from ngrok.global_cache import GLOBAL_CACHE
from ngrok.util import tolen, generate_auth_resp, generate_new_tunnel
from ngrok.config import CONFIG_FILE_PATH, DEFAULT_PEM_FILE, DEFAULT_KEY_FILE, DEFAULT_BUF_SIZE
from ngrok.controler.ngrok_controller import NgrokController

DEFAULT_SERVER_DOMAIN = 'localhost.com'
DEFAULT_SERVER_HOST = '127.0.0.1'
DEFAULT_SERVER_HTTP = 28080
DEFAULT_SERVER_HTTPS = 24443
DEFAULT_SERVER_PORT = 14443


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


class NgrokHandler:

    def __init__(self, conn, loop):

        self.conn = conn
        self.loop = loop
        self.fd = conn.fileno()

        self.binary_data = None

        self.resp_list = []
        self.writing_resp = None

    def read_handler(self):
        """
         处理read回调。
        :return:
        """
        try:
            data = self.conn.recv(DEFAULT_BUF_SIZE)
        except ssl.SSLWantReadError:
            return

        if not data:
            self.loop.remove_reader(self.conn.fileno())
            self.conn.close()
        else:
            request_size = tolen(data[:8])

            if request_size > len(data[8:]):
                # 请求没接收全，继续接受

                self.binary_data = bytearray(data)

                # 移除旧的read回调
                self.loop.remove_reader(self.fd)
                # 因为请求未接受完, 使用继续接收的read回调
                self.loop.add_reader(self.fd, self.continue_read_handler)
            elif request_size == len(data[8:]):
                # 请求接受全

                request_data = data[8:]
                logger.debug("receive control request: %s", request_data)

                # TODO: 在这里要做处理请求
                self.process_request(request_data)

                self.loop.remove_reader(self.fd)
            else:

                request_data = data[8:request_size + 8]
                # TODO: 在这里要做处理请求
                self.process_request(request_data)

                # 有TCP粘包
                self.binary_data = bytearray(data[request_size + 8:])

    def continue_read_handler(self):
        """
        处理read回调。用来处理请求过大没有一次接收完的。
        :return:
        """
        try:
            data = self.conn.recv(DEFAULT_BUF_SIZE)

        except ssl.SSLWantReadError as ex:
            logger.debug("SSLWantReadError")
            return

        if not data:
            self.loop.remove_reader(self.conn.fileno())
            self.conn.close()
        else:
            request_size = tolen(self.binary_data[:8])
            print('request_size:' + str(request_size))
            try:
                self.binary_data.extend(data)
            except Exception as ex:
                logger.exception("test:", exc_info=ex)
            if request_size > len(self.binary_data[8:]):
                # 请求没接收全，继续接受
                pass
            elif request_size < len(self.binary_data[8:]):
                # 请求的大小，小于收到的大小，有TCP粘包

                # 获取本次请求
                request_data = self.binary_data[8: 8 + request_size]

                logger.debug("receive control request: %s", request_data)
                # TODO: 在这里要做处理请求
                self.process_request(request_data)

                # 移除已处理请求的数据
                self.binary_data = self.binary_data[8 + request_size:]

                # 移除继续读的read回调
                self.loop.remove_reader(self.fd)
            else:
                # 请求接受全
                request_data = self.binary_data[8:]
                logger.debug("receive control request: %s", request_data)

                # TODO: 在这里要做处理请求
                self.process_request(request_data)

                self.binary_data = None

                # 移除继续读的read回调
                self.loop.remove_reader(self.fd)

    def write_handler(self):
        """
        处理写回调。
        :return:
        """

        if len(self.resp_list) == 0 and self.writing_resp is None:
            self.loop.remove_writer(self.fd)
            self.process_error()
            return

        try:

            if self.writing_resp is None:
                self.writing_resp = self.resp_list.pop()

            sent_bytes = self.conn.send(self.writing_resp)
            if sent_bytes < len(self.writing_resp):
                self.writing_resp = self.writing_resp[sent_bytes:]
            else:
                self.writing_resp = None
                self.loop.remove_writer(self.fd)
                self.loop.add_reader(self.fd, self.read_handler)

        except ssl.SSLWantReadError as ex:
            logger.debug("SSLWantReadError")
            return

    def process_request(self, request_data):
        """
        处理读取到的请求命令
        :param request_data: 读取到的请求数据，会在本函数中转为json格式
        :return:
        """
        try:
            request = json.loads(str(request_data, 'utf-8'))
        except Exception as ex:
            logger.exception("Exception in process_request, load request:", exc_info=ex)
            self.process_error()
            return

        req_type = request.get('Type', None)

        if req_type == 'Auth':
            err, msg, resp = self.auth_process(request)
        elif req_type == 'ReqTunnel':
            pass
            # err, msg, resp = self.req_tunnel_process(req_json, fd)
        elif req_type == 'RegProxy':
            pass
            # err, msg, resp = self.reg_proxy_process(req_json, fd)
        elif req_type == 'Ping':
            pass
            # err, msg, resp = self.ping_process(req_json, fd)
        else:
            # unknown req type, close this connection
            # self.process_error()
            err, msg, data = ERR_UNKNOWN_REQUEST, get_err_msg(ERR_UNKNOWN_REQUEST), None

        if err == ERR_UNKNOWN_REQUEST:
            self.process_error()
        elif err == ERR_SUCCESS:
            self.resp_list.append(resp)
            self.loop.remove_reader(self.fd)
            self.loop.remove_reader(self.fd)
            self.loop.add_writer(self.fd, self.write_handler)

    def auth_process(self, request):
        """
        process auth
        :param request:
        :return: (err_code, msg, binary response data)
        """
        user = request['Payload'].get('User')
        pwd = request['Payload'].get('Password')
        version = request['Payload'].get('Version')
        mm_version = request['Payload'].get('MmVersion')
        os_type = request['Payload'].get('OS')
        arch = request['Payload'].get('Arch')

        err, msg, client_id = NgrokController.auth(user, pwd, version, mm_version, os_type, arch)
        logger.debug('auth process: err[%d], msg[%s], client_id[%s]', err, msg, client_id)

        if err != ERR_SUCCESS:
            resp = generate_auth_resp(error=msg)
        else:
            GLOBAL_CACHE.add_client_id(client_id)
            GLOBAL_CACHE.add_control_socket(self.fd, client_id)
            resp = generate_auth_resp(client_id=client_id)

        return err, msg, resp

    def req_tunnel_process(self, request):
        """
        Process ReqTunnel request
        :param request:
        :return: (err_code, msg, binary response data)
        """

        if self.fd not in GLOBAL_CACHE.CONTROL_SOCKET:
            err = ERR_UNREGISTERED_CLIENT_ID
            msg = get_err_msg(ERR_UNREGISTERED_CLIENT_ID)
            return err, msg, generate_new_tunnel(msg)

        req_id = request['Payload'].get('ReqId')
        protocol = request['Payload'].get('Protocol')

        if protocol in ('http', 'https'):
            hostname = request['Payload'].get('Hostname')
            subdomain = request['Payload'].get('Subdomain')
            http_auth = request['Payload'].get('HttpAuth')

            err, msg, url = NgrokController.req_tunnel_http(req_id, protocol, hostname, subdomain, http_auth)

            if err != ERR_SUCCESS:
                return err, msg, generate_new_tunnel(msg)

            if url in GLOBAL_CACHE.HOSTS:
                err = ERR_URL_EXISTED
                msg = get_err_msg(ERR_URL_EXISTED)
                return err, msg, generate_new_tunnel(msg)

            GLOBAL_CACHE.add_host(url, self.fd)


        elif protocol == 'tcp':
            # TODO: Fixed me ! TCP not support!!
            remote_port = request['Payload'].get('RemotePort')

            err = ERR_UNSUPPORTED_PROTOCOL
            msg = get_err_msg(ERR_UNSUPPORTED_PROTOCOL)

            return err, msg, generate_new_tunnel(msg)

    def process_error(self):
        """
        处理错误，关闭客户端连接，移除所有事件监听。比如：解析命令出错等
        :return:
        """
        self.loop.remove_reader(self.fd)
        self.loop.remove_writer(self.fd)

        client_id = GLOBAL_CACHE.pop_control_socket(self.fd)

        proxy_socket_list = GLOBAL_CACHE.pop_client_id(client_id)
        # TODO: Fixed me, may be should close all the proxy socket here

        # TODO: url
        # GLOBAL_CACHE.pop_host()


        try:
            self.conn.close()
        except Exception as ex:
            logger.exception("Exception in process error:", exc_info=ex)


event_loop = asyncio.get_event_loop()

s = BaseService(event_loop, NgrokHandler, is_ssl=True, cert_file=CONFIG_FILE_PATH + DEFAULT_PEM_FILE, key_file=CONFIG_FILE_PATH + DEFAULT_KEY_FILE)

event_loop.set_debug(True)

# task = event_loop.create_task(s.start)
event_loop.run_until_complete(s.start())

from http .server import HTTPServer