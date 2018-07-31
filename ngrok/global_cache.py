#!/usr/bin/env python
# -*- coding: UTF-8 -*-
from asyncio import Queue


class GlobalCache(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(GlobalCache, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):

        # key: url, value: {"fd": fd, 'client_id': client_id, "send_req_proxy": coroutine function, }
        self.HOSTS = dict()

        # key: client_id, value: {'http': [url, url,...], 'https': [url, url, ..], 'tcp': [port, port, ..]}
        self.TUNNEL_LIST = dict()

        # key: communicate_identify, value: [
        #                        {'http_resp_queue': Queue, // 给ngrok_handler来插入返回给浏览器的响应
        #                         'http_req_queue': Queue // 给http_handler来插入浏览器给服务端（client）的请求
        #                         'control_http_queue': Queue // 用来发送控制信息的消息队列，针对浏览器->服务端的连接, 让 http_handler 控制 ngrok_handler(命令有: close)
        #                         'control_proxy_queue': Queue // 用来发送控制信息的消息队列，针对客户端->服务端的连接, 让 ngrok_handler 控制 http_handler(命令有: close)
        #                        },
        #                        ...]
        # communicate_identify = md5(client_id + browser_addr + timestamp)
        self.HTTP_COMMU_QUEUE_MAP = dict()

        # key: client id, value: Queue()
        self.SEND_REQ_PROXY_LIST = dict()

        # key: client id, value: Queue([{'url': url, 'addr': addr}, ...])
        self.PROXY_URL_ADDR_LIST = dict()

    def add_client_id(self, client_id):
        """
        add new client id
        :return:
        """
        self.SEND_REQ_PROXY_LIST[client_id] = Queue()
        self.PROXY_URL_ADDR_LIST[client_id] = Queue()

    def init_http_commu_queue_map(self, communicate_identify):
        """
        初始化对应的communicate_identify的两个消息队列
        :param communicate_identify:
        :return:
        """
        self.HTTP_COMMU_QUEUE_MAP[communicate_identify] = dict()
        queue_map = self.HTTP_COMMU_QUEUE_MAP[communicate_identify]
        queue_map['http_resp_queue'] = Queue()
        queue_map['http_req_queue'] = Queue()
        queue_map['control_http_queue'] = Queue()
        queue_map['control_proxy_queue'] = Queue()

    def del_http_commu_queue_map(self, communicate_identify):
        """
        删除对应communicate_identify中的消息队列通道（Queue, Redis...）
        :param communicate_identify:
        :return:
        """
        if communicate_identify in self.HTTP_COMMU_QUEUE_MAP:
            queue_map = self.HTTP_COMMU_QUEUE_MAP.pop(communicate_identify)
            if queue_map:
                queue_map.pop('http_resp_queue')
                queue_map.pop('http_req_queue')
                queue_map.pop('control_http_queue')
                queue_map.pop('control_proxy_queue')

    def add_host(self, url, fd, client_id, send_req_proxy):
        """
        Add url info to HOSTS
        :param url:
        :param fd:
        :param client_id:
        :param send_req_proxy: coroutine function
        :return:
        """
        host_info = {'fd': fd, 'client_id': client_id, 'send_req_proxy': send_req_proxy}
        self.HOSTS[url] = host_info

    def pop_host(self, url):
        """
        Pop with fd. The fd will be removed
        :param url:
        :return: {'fd': fd, 'client_id': client_id, 'send_req_proxy': send_req_proxy}
        """
        return self.HOSTS.pop(url)

    def add_tunnel(self, client_id, protocol, url=None, port=None):
        """
        Add tunnel url(http/https) or port(tcp) to TUNNEL_LIST
        :param client_id:
        :param protocol: http/https/tcp
        :param url: if protocol is http/https, it is necessary
        :param port: if protocol is tcp, it is necessary
        :return:
        """
        if client_id not in self.TUNNEL_LIST:
            self.TUNNEL_LIST[client_id] = {'http': [], 'https': [], 'tcp': []}

        if protocol == 'http':
            self.TUNNEL_LIST[client_id]['http'].append(url)
        elif protocol == 'https':
            self.TUNNEL_LIST[client_id]['http'].append(url)
        elif protocol == 'tcp':
            self.TUNNEL_LIST[client_id]['http'].append(port)

    def pop_tunnel(self, client_id):
        """
        Pop with client_id. The client_id will be removed
        :param client_id:
        :return: {'http': [url, url, ...], 'https': [url, url, ...], 'tcp':[port, port, ...]}
        """
        if client_id in self.TUNNEL_LIST:
            return self.TUNNEL_LIST.pop(client_id)
        return None

GLOBAL_CACHE = GlobalCache()