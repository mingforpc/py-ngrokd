#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import ssl
import time
import asyncio
from ngrok.logger import logger
from ngrok.util import get_http_headers
from ngrok.global_cache import GLOBAL_CACHE
from ngrok.config import DEFAULT_BUF_SIZE
from ngrok.util import md5


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

            self.url = None

            # 这个http请求将会关联到的client id
            self.client_id = None

            # 用来与 相关联的 proxy socket 在消息队列(Queue, redis...)中进行通信的标识
            self.communicate_identify = None

            # 用来接受来之ngrok_handler的控制信息的消息队列
            self.control_http_queue = None

            # 用来发送给ngrok_handler的控制信息的消息队列
            self.control_proxy_queue = None

        def read_handler(self):
            asyncio.ensure_future(self.__read_handler(), loop=self.loop)

        async def __read_handler(self):
            """
            处理read回调
            :return:
            """
            try:
                data = self.conn.recv(DEFAULT_BUF_SIZE)
            except ssl.SSLWantReadError:
                return

            if not data:
                asyncio.ensure_future(self.process_error(), loop=self.loop)
            else:
                headers = get_http_headers(data.decode('utf-8'))

                if 'HOST' in headers:
                    url = self.protocol + '://' + headers['HOST']

                    if url in GLOBAL_CACHE.HOSTS:
                        self.binary_data = data
                        self.url = url

                        logger.debug("Http request for url[%s]", url)

                        self.client_id = GLOBAL_CACHE.HOSTS[url]['client_id']

                        await self.set_url_and_addr()

                        # TODO: 用协程在这里让 NgrokHandler 中的 socket 发送一个ReqProxy命令到客户端，并等待一个proxy连接上。尽可能使用异步的方式
                        queue = GLOBAL_CACHE.SEND_REQ_PROXY_LIST[self.client_id]
                        asyncio.ensure_future(queue.put('send'), loop=self.loop)

                        # 添加处理proxy意外断开的处理事件
                        asyncio.ensure_future(self.close_by_ngrok(), loop=self.loop)

                        # 将接收到的http 请求内容 插入消息队列中
                        await self.insert_data_to_http_req_queue()

                        asyncio.ensure_future(self.write_resp_to_browser(), loop=self.loop)
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

            self.resp_list.append(buf.encode('utf-8'))

            self.loop.remove_reader(self.fd)
            self.loop.add_writer(self.fd, self.write_handler)

        def write_handler(self):
            """

            :return:
            """
            asyncio.ensure_future(self.__write_handler(), loop=self.loop)

        async def __write_handler(self):
            """
            处理写回调。
            :return:
            """
            if len(self.resp_list) == 0 and self.writing_resp is None:
                return

            try:

                if self.writing_resp is None:
                    self.writing_resp = self.resp_list[0]
                    self.resp_list = self.resp_list[1:]

                sent_bytes = self.conn.send(self.writing_resp)
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
                asyncio.ensure_future(self.process_error(), loop=self.loop)

        async def set_url_and_addr(self):
            """
            将url和 浏览器客户端的网络地址 设置到queue中
            :return:
            """
            socket_info = self.conn.getpeername()
            browser_addr = socket_info[0] + ':' + str(socket_info[1])

            # 使用 communicate_identify 在消息队列(Queue, redis..)中进行交换数据
            self.communicate_identify = self.__generate_identify(browser_addr)
            # 初始化消息队列
            GLOBAL_CACHE.init_http_commu_queue_map(self.communicate_identify)

            self.control_http_queue = GLOBAL_CACHE.HTTP_COMMU_QUEUE_MAP[self.communicate_identify]['control_http_queue']
            self.control_proxy_queue = GLOBAL_CACHE.HTTP_COMMU_QUEUE_MAP[self.communicate_identify]['control_proxy_queue']

            url_and_addr = {'url': self.url, 'addr': browser_addr, 'communicate_identify': self.communicate_identify}
            queue = GLOBAL_CACHE.PROXY_URL_ADDR_LIST[self.client_id]
            logger.debug(queue)
            await queue.put(url_and_addr)

        def __generate_identify(self, browser_addr):
            """
            通过 MD5(client_id + browser_addr + timestamp) 生成一个与 proxy socket相关联的唯一标识。
            以后 http socket 可以通过这个标识在消息队列（Queue，redis...）中与 proxy socket进行通信。
            :return:
            """
            str_val = str(self.client_id) + str(browser_addr) + str(time.time())
            return md5(str_val)

        def insert_resp_list(self, resp):
            """
            将resp插入队列末尾
            :param resp:
            :return:
            """
            self.resp_list.append(resp)

        async def insert_data_to_http_req_queue(self):
            """
            将 http 接收到的请求数据，插入到对应的消息队列（Queue，redis...）中，等待ngrok_handler发送给客户端
            :return:
            """
            queue_map = GLOBAL_CACHE.HTTP_COMMU_QUEUE_MAP[self.communicate_identify]
            if queue_map:
                http_req_queue = queue_map.get('http_req_queue')
                if http_req_queue:
                    await http_req_queue.put(self.binary_data)

        async def get_http_resp_from_queue(self):
            """
            从消息队列(Queue, redis...)获取Http response内容
            :return:
            """
            queue_map = GLOBAL_CACHE.HTTP_COMMU_QUEUE_MAP[self.communicate_identify]
            if queue_map:
                http_resp_queue = queue_map.get('http_resp_queue')
                if http_resp_queue:
                    return await http_resp_queue.get()

        async def process_error(self):
            """
            处理错误，关闭客户端连接，移除所有事件监听。比如：解析命令出错等
            :return:
            """

            self.loop.remove_reader(self.fd)
            self.loop.remove_writer(self.fd)

            # 检查queue是否存在并尝试通知proxy连接关闭
            if self.control_proxy_queue:
                await self.control_proxy_queue.put('close')

            GLOBAL_CACHE.del_http_commu_queue_map(self.communicate_identify)
            try:
                self.conn.close()
            except Exception as ex:
                logger.exception("Exception in process error:", exc_info=ex)

        async def write_resp_to_browser(self):
            """
            循环写输入到浏览器
            :return:
            """
            while True:
                resp_data = await self.get_http_resp_from_queue()
                self.resp_list.append(resp_data)
                self.loop.add_writer(self.fd, self.write_handler)

        async def close_by_ngrok(self):
            """
            通过 control_http_queue 获取 close 的消息，接收到之后关闭连接。
            该方法的目的是处理，当proxy连接意外断掉的时候，同时也把http连接断开
            :return:
            """
            if self.control_http_queue:
                signal = await self.control_http_queue.get()
                if signal == 'close':
                    asyncio.ensure_future(self.process_error(), loop=self.loop)
