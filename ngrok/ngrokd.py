#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import os
import ssl
import abc
import socket
import asyncio
from ngrok.logger import logger


DEFAULT_SERVER_DOMAIN = 'localhost.com'
DEFAULT_SERVER_HOST = '127.0.0.1'
DEFAULT_SERVER_HTTP = 28080
DEFAULT_SERVER_HTTPS = 24443
DEFAULT_SERVER_PORT = 14443



class BaseService(abc.ABC):

    def __init__(self, host, port, event_loop, ssl=False, hostname=None, cert_file=None, key_file=None, listen=100):
        self.host = host
        self.port = port
        self.event_loop = event_loop
        self.ssl = ssl
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
            if self.ssl and (self.cert_file is None or self.key_file is None):
                raise Exception("If you want to enable ssl, please set cert_file and key_file")

            if self.ssl:
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

        if self.running:
            return

        if not self.initialized:
            self.initialize()

        self.running = True

        while self.running:
            await self.handle_connect()

    async def handle_connect(self):
        conn, address = await self.event_loop.sock_accept(self.__socket)
        if ssl:
            conn = self.context.wrap_socket(conn, server_side=True, do_handshake_on_connect=False,
                                            server_hostname=self.hostname)


event_loop = asyncio.get_event_loop()

s = BaseService('0.0.0.0', 5000, event_loop)

event_loop.set_debug(True)

# task = event_loop.create_task(s.start)
event_loop.run_until_complete(s.start())

# 如何用协程建立ssl， copy from asyncio.selector_events
# class _SelectorSslTransport(_SelectorTransport):
#
#     _buffer_factory = bytearray
#
#     def __init__(self, loop, rawsock, protocol, sslcontext, waiter=None,
#                  server_side=False, server_hostname=None,
#                  extra=None, server=None):
#         if ssl is None:
#             raise RuntimeError('stdlib ssl module not available')
#
#         if not sslcontext:
#             sslcontext = sslproto._create_transport_context(server_side, server_hostname)
#
#         wrap_kwargs = {
#             'server_side': server_side,
#             'do_handshake_on_connect': False,
#         }
#         if server_hostname and not server_side:
#             wrap_kwargs['server_hostname'] = server_hostname
#         sslsock = sslcontext.wrap_socket(rawsock, **wrap_kwargs)
#
#         super().__init__(loop, sslsock, protocol, extra, server)
#         # the protocol connection is only made after the SSL handshake
#         self._protocol_connected = False
#
#         self._server_hostname = server_hostname
#         self._waiter = waiter
#         self._sslcontext = sslcontext
#         self._paused = False
#
#         # SSL-specific extra info.  (peercert is set later)
#         self._extra.update(sslcontext=sslcontext)
#
#         if self._loop.get_debug():
#             logger.debug("%r starts SSL handshake", self)
#             start_time = self._loop.time()
#         else:
#             start_time = None
#         self._on_handshake(start_time)
#
#     def _wakeup_waiter(self, exc=None):
#         if self._waiter is None:
#             return
#         if not self._waiter.cancelled():
#             if exc is not None:
#                 self._waiter.set_exception(exc)
#             else:
#                 self._waiter.set_result(None)
#         self._waiter = None
#
#     def _on_handshake(self, start_time):
#         try:
#             self._sock.do_handshake()
#         except ssl.SSLWantReadError:
#             self._loop._add_reader(self._sock_fd,
#                                    self._on_handshake, start_time)
#             return
#         except ssl.SSLWantWriteError:
#             self._loop._add_writer(self._sock_fd,
#                                    self._on_handshake, start_time)
#             return
#         except BaseException as exc:
#             if self._loop.get_debug():
#                 logger.warning("%r: SSL handshake failed",
#                                self, exc_info=True)
#             self._loop._remove_reader(self._sock_fd)
#             self._loop._remove_writer(self._sock_fd)
#             self._sock.close()
#             self._wakeup_waiter(exc)
#             if isinstance(exc, Exception):
#                 return
#             else:
#                 raise
#
#         self._loop._remove_reader(self._sock_fd)
#         self._loop._remove_writer(self._sock_fd)
#
#         peercert = self._sock.getpeercert()
#         if not hasattr(self._sslcontext, 'check_hostname'):
#             # Verify hostname if requested, Python 3.4+ uses check_hostname
#             # and checks the hostname in do_handshake()
#             if (self._server_hostname and
#                 self._sslcontext.verify_mode != ssl.CERT_NONE):
#                 try:
#                     ssl.match_hostname(peercert, self._server_hostname)
#                 except Exception as exc:
#                     if self._loop.get_debug():
#                         logger.warning("%r: SSL handshake failed "
#                                        "on matching the hostname",
#                                        self, exc_info=True)
#                     self._sock.close()
#                     self._wakeup_waiter(exc)
#                     return
#
#         # Add extra info that becomes available after handshake.
#         self._extra.update(peercert=peercert,
#                            cipher=self._sock.cipher(),
#                            compression=self._sock.compression(),
#                            ssl_object=self._sock,
#                            )
#
#         self._read_wants_write = False
#         self._write_wants_read = False
#         self._loop._add_reader(self._sock_fd, self._read_ready)
#         self._protocol_connected = True
#         self._loop.call_soon(self._protocol.connection_made, self)
#         # only wake up the waiter when connection_made() has been called
#         self._loop.call_soon(self._wakeup_waiter)
#
#         if self._loop.get_debug():
#             dt = self._loop.time() - start_time
#             logger.debug("%r: SSL handshake took %.1f ms", self, dt * 1e3)
#
#     def pause_reading(self):
#         # XXX This is a bit icky, given the comment at the top of
#         # _read_ready().  Is it possible to evoke a deadlock?  I don't
#         # know, although it doesn't look like it; write() will still
#         # accept more data for the buffer and eventually the app will
#         # call resume_reading() again, and things will flow again.
#
#         if self._closing:
#             raise RuntimeError('Cannot pause_reading() when closing')
#         if self._paused:
#             raise RuntimeError('Already paused')
#         self._paused = True
#         self._loop._remove_reader(self._sock_fd)
#         if self._loop.get_debug():
#             logger.debug("%r pauses reading", self)
#
#     def resume_reading(self):
#         if not self._paused:
#             raise RuntimeError('Not paused')
#         self._paused = False
#         if self._closing:
#             return
#         self._loop._add_reader(self._sock_fd, self._read_ready)
#         if self._loop.get_debug():
#             logger.debug("%r resumes reading", self)
#
#     def _read_ready(self):
#         if self._conn_lost:
#             return
#         if self._write_wants_read:
#             self._write_wants_read = False
#             self._write_ready()
#
#             if self._buffer:
#                 self._loop._add_writer(self._sock_fd, self._write_ready)
#
#         try:
#             data = self._sock.recv(self.max_size)
#         except (BlockingIOError, InterruptedError, ssl.SSLWantReadError):
#             pass
#         except ssl.SSLWantWriteError:
#             self._read_wants_write = True
#             self._loop._remove_reader(self._sock_fd)
#             self._loop._add_writer(self._sock_fd, self._write_ready)
#         except Exception as exc:
#             self._fatal_error(exc, 'Fatal read error on SSL transport')
#         else:
#             if data:
#                 self._protocol.data_received(data)
#             else:
#                 try:
#                     if self._loop.get_debug():
#                         logger.debug("%r received EOF", self)
#                     keep_open = self._protocol.eof_received()
#                     if keep_open:
#                         logger.warning('returning true from eof_received() '
#                                        'has no effect when using ssl')
#                 finally:
#                     self.close()
#
#     def _write_ready(self):
#         if self._conn_lost:
#             return
#         if self._read_wants_write:
#             self._read_wants_write = False
#             self._read_ready()
#
#             if not (self._paused or self._closing):
#                 self._loop._add_reader(self._sock_fd, self._read_ready)
#
#         if self._buffer:
#             try:
#                 n = self._sock.send(self._buffer)
#             except (BlockingIOError, InterruptedError, ssl.SSLWantWriteError):
#                 n = 0
#             except ssl.SSLWantReadError:
#                 n = 0
#                 self._loop._remove_writer(self._sock_fd)
#                 self._write_wants_read = True
#             except Exception as exc:
#                 self._loop._remove_writer(self._sock_fd)
#                 self._buffer.clear()
#                 self._fatal_error(exc, 'Fatal write error on SSL transport')
#                 return
#
#             if n:
#                 del self._buffer[:n]
#
#         self._maybe_resume_protocol()  # May append to buffer.
#
#         if not self._buffer:
#             self._loop._remove_writer(self._sock_fd)
#             if self._closing:
#                 self._call_connection_lost(None)
#
#     def write(self, data):
#         if not isinstance(data, (bytes, bytearray, memoryview)):
#             raise TypeError('data argument must be a bytes-like object, '
#                             'not %r' % type(data).__name__)
#         if not data:
#             return
#
#         if self._conn_lost:
#             if self._conn_lost >= constants.LOG_THRESHOLD_FOR_CONNLOST_WRITES:
#                 logger.warning('socket.send() raised exception.')
#             self._conn_lost += 1
#             return
#
#         if not self._buffer:
#             self._loop._add_writer(self._sock_fd, self._write_ready)
#
#         # Add it to the buffer.
#         self._buffer.extend(data)
#         self._maybe_pause_protocol()
#
#     def can_write_eof(self):
#         return False