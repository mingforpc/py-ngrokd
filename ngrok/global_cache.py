
class GlobalCache(object):
    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(GlobalCache, cls).__new__(cls, *args, **kwargs)
        return cls._instance

    def __init__(self):

        # key: url, value: {"fd": fd}
        self.HOSTS = dict()

        # key: client_id, value: {'http': [url, url,...], 'https': [url, url, ..], 'tcp': [port, port, ..]}
        self.TUNNEL_LIST = dict()

        # key: client id, value: list of ProxySocket object
        self.PROXY_SOCKET_LIST = dict()

        # key: fd, value: client id
        # self.CONTROL_SOCKET = dict()

    def add_client_id(self, client_id):
        """
        add new client id
        :return:
        """
        self.PROXY_SOCKET_LIST[client_id] = []

    def pop_client_id(self, client_id):
        """
        Pop with client id, the client id will be removed
        :param client_id:
        :return:
        """
        return self.PROXY_SOCKET_LIST.pop(client_id)

    # def add_control_socket(self, fd, client_id):
    #     """
    #     add new control socket, bind with client id
    #     :param fd:
    #     :param client_id:
    #     :return:
    #     """
    #     self.CONTROL_SOCKET[fd] = client_id
    #
    # def pop_control_socket(self, fd):
    #     """
    #     Pop with fd. The fd will be removed
    #     :param fd:
    #     :return: client_id
    #     """
    #     return self.CONTROL_SOCKET.pop(fd)

    def add_host(self, url, fd):
        """
        Add url info to HOSTS
        :param url:
        :param fd:
        :return:
        """
        host_info = {'fd': fd}
        self.HOSTS[url] = host_info

    def pop_host(self, url):
        """
        Pop with fd. The fd will be removed
        :param url:
        :return: {'fd': fd}
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
            self.TUNNEL_LIST[client_id]['http'] += url
        elif protocol == 'https':
            self.TUNNEL_LIST[client_id]['http'] += url
        elif protocol == 'tcp':
            self.TUNNEL_LIST[client_id]['http'] += port

GLOBAL_CACHE = GlobalCache()