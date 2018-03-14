#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import ssl
import asyncio
from ngrok.logger import logger
from ngrok.util import get_http_headers
from ngrok.global_cache import GLOBAL_CACHE
from ngrok.config import DEFAULT_BUF_SIZE


class HttpHandler:

    protocol = 'http'

    def __init__(self, conn, loop):
        """

        :param conn: client socket
        :param loop: event loop
        """
        self.conn = conn
        self.loop = loop

        self.fd = conn.fileno()

        self.binary_data = None

        self.resp_list = []
        self.writing_resp = None

    def read_handler(self):
        """
        处理read回调
        :return:
        """
        try:
            data = self.conn.recv(DEFAULT_BUF_SIZE)
        except ssl.SSLWantReadError:
            return

        if not data:
            self.process_error()
        else:
            headers = get_http_headers(data.decode('utf-8'))

            if 'HOST' in headers:
                url = self.protocol + '://' + headers['HOST']

                if url in GLOBAL_CACHE.HOSTS:
                    logger.debug("Http request for url[%s]", url)

                    # TODO: 用协程在这里让 NgrokHandler 中的 socket 发送一个ReqProxy命令到客户端，并等待一个proxy连接上。尽可能使用异步的方式
                    send_req_proxy = GLOBAL_CACHE.HOSTS[url]['send_req_proxy']

                    asyncio.ensure_future(send_req_proxy(), loop=self.loop)

                else:
                    logger.debug("Http request for url[%s], no such url, return 404", url)

                    # Can not find the tunnel
                    # Return 404 to browser
                    self.send_404(headers['HOST'])
            else:
                # No 'HOST' in http headers
                self.send_404('without host in header')

    def send_404(self, host):
        html = 'Tunnel %s not found' % host
        header = 'HTTP/1.0 404 Not Found\r\n'
        header += 'Content-Length: %d\r\n'
        header += "\r\n" + "%s"
        buf = header % (len(html.encode('utf-8')), html)

        self.resp_list.append(buf)

        self.loop.remove_reader(self.fd)
        self.loop.add_writer(self.fd, self.write_handler)

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

            sent_bytes = self.conn.send(self.writing_resp.encode('utf-8'))
            if sent_bytes < len(self.writing_resp):
                self.writing_resp = self.writing_resp[sent_bytes:]
            else:
                self.writing_resp = None
                self.loop.remove_writer(self.fd)
                self.loop.add_reader(self.fd, self.read_handler)

        except ssl.SSLWantReadError as ex:
            logger.debug("SSLWantReadError")
        except Exception as ex:
            logger.exception("Exception in write_handler:", exc_info=ex)
            self.process_error()

    def process_error(self):
        """
        处理错误，关闭客户端连接，移除所有事件监听。比如：解析命令出错等
        :return:
        """
        self.loop.remove_reader(self.conn.fileno())
        self.conn.close()