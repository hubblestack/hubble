# -*- coding: utf-8 -*-
'''
IPC transport classes
'''

# Import Python libs
from __future__ import absolute_import, print_function, unicode_literals
import errno
import logging
import socket
import time

# Import 3rd-party libs
import msgpack

# Import Tornado libs
import tornado
import tornado.gen
import tornado.netutil
import tornado.concurrent
from tornado.locks import Lock
from tornado.ioloop import IOLoop, TimeoutError as TornadoTimeoutError
from tornado.iostream import IOStream, StreamClosedError

import hubblestack.transport.frame
import hubblestack.utils.asynchronous

log = logging.getLogger(__name__)


# 'tornado.concurrent.Future' doesn't support
# remove_done_callback() which we would have called
# in the timeout case. Due to this, we have this
# callback function outside of FutureWithTimeout.
def future_with_timeout_callback(future):
    if future._future_with_timeout is not None:
        future._future_with_timeout._done_callback(future)


class IPCClient(object):
    '''
    A Tornado IPC client very similar to Tornado's TCPClient class
    but using either UNIX domain sockets or TCP sockets

    This was written because Tornado does not have its own IPC
    server/client implementation.

    :param IOLoop io_loop: A Tornado ioloop to handle scheduling
    :param str/int socket_path: A path on the filesystem where a socket
                                belonging to a running IPCServer can be
                                found.
                                It may also be of type 'int', in which
                                case it is used as the port for a tcp
                                localhost connection.
    '''
    def __init__(self, socket_path, io_loop=None):
        '''
        Create a new IPC client

        IPC clients cannot bind to ports, but must connect to
        existing IPC servers. Clients can then send messages
        to the server.

        '''
        self.io_loop = io_loop or tornado.ioloop.IOLoop.current()
        self.socket_path = socket_path
        self._closing = False
        self.stream = None
        # msgpack deprecated `encoding` starting with version 0.5.2
        if msgpack.version >= (0, 5, 2):
            # Under Py2 we still want raw to be set to True
            msgpack_kwargs = {'raw': False}
        else:
            msgpack_kwargs = {'encoding': 'utf-8'}
        self.unpacker = msgpack.Unpacker(**msgpack_kwargs)

    def connected(self):
        return self.stream is not None and not self.stream.closed()

    def connect(self, callback=None, timeout=None):
        '''
        Connect to the IPC socket
        '''
        if hasattr(self, '_connecting_future') and not self._connecting_future.done():  # pylint: disable=E0203
            future = self._connecting_future  # pylint: disable=E0203
        else:
            if hasattr(self, '_connecting_future'):
                # read previous future result to prevent the "unhandled future exception" error
                self._connecting_future.exception()  # pylint: disable=E0203
            future = tornado.concurrent.Future()
            self._connecting_future = future
            self._connect(timeout=timeout)

        if callback is not None:
            def handle_future(future):
                response = future.result()
                self.io_loop.add_callback(callback, response)
            future.add_done_callback(handle_future)

        return future

    @tornado.gen.coroutine
    def _connect(self, timeout=None):
        '''
        Connect to a running IPCServer
        '''
        if isinstance(self.socket_path, int):
            sock_type = socket.AF_INET
            sock_addr = ('127.0.0.1', self.socket_path)
        else:
            sock_type = socket.AF_UNIX
            sock_addr = self.socket_path

        self.stream = None
        if timeout is not None:
            timeout_at = time.time() + timeout

        while True:
            if self._closing:
                break

            if self.stream is None:
                with hubblestack.utils.asynchronous.current_ioloop(self.io_loop):
                    self.stream = IOStream(
                        socket.socket(sock_type, socket.SOCK_STREAM)
                    )
            try:
                log.trace('IPCClient: Connecting to socket: %s', self.socket_path)
                yield self.stream.connect(sock_addr)
                self._connecting_future.set_result(True)
                break
            except Exception as e:
                if self.stream.closed():
                    self.stream = None

                if timeout is None or time.time() > timeout_at:
                    if self.stream is not None:
                        self.stream.close()
                        self.stream = None
                    self._connecting_future.set_exception(e)
                    break

                yield tornado.gen.sleep(1)

    def __del__(self):
        try:
            self.close()
        except socket.error as exc:
            if exc.errno != errno.EBADF:
                # If its not a bad file descriptor error, raise
                raise
        except TypeError:
            # This is raised when Python's GC has collected objects which
            # would be needed when calling self.close()
            pass

    def close(self):
        '''
        Routines to handle any cleanup before the instance shuts down.
        Sockets and filehandles should be closed explicitly, to prevent
        leaks.
        '''
        if self._closing:
            return

        self._closing = True

        log.debug('Closing %s instance', self.__class__.__name__)

        if self.stream is not None and not self.stream.closed():
            self.stream.close()


class IPCMessageClient(IPCClient):
    '''
    Salt IPC message client

    Create an IPC client to send messages to an IPC server

    An example of a very simple IPCMessageClient connecting to an IPCServer. This
    example assumes an already running IPCMessage server.

    IMPORTANT: The below example also assumes a running IOLoop process.

    # Import Tornado libs
    import tornado.ioloop

    # Import Salt libs
    import salt.config
    import salt.transport.ipc

    io_loop = tornado.ioloop.IOLoop.current()

    ipc_server_socket_path = '/var/run/ipc_server.ipc'

    ipc_client = salt.transport.ipc.IPCMessageClient(ipc_server_socket_path, io_loop=io_loop)

    # Connect to the server
    ipc_client.connect()

    # Send some data
    ipc_client.send('Hello world')
    '''
    # FIXME timeout unimplemented
    # FIXME tries unimplemented
    @tornado.gen.coroutine
    def send(self, msg, timeout=None, tries=None):
        '''
        Send a message to an IPC socket

        If the socket is not currently connected, a connection will be established.

        :param dict msg: The message to be sent
        :param int timeout: Timeout when sending message (Currently unimplemented)
        '''
        if not self.connected():
            yield self.connect()
        pack = hubblestack.transport.frame.frame_msg_ipc(msg, raw_body=True)
        yield self.stream.write(pack)


class IPCMessageSubscriber(IPCClient):
    '''
    Salt IPC message subscriber

    Create an IPC client to receive messages from IPC publisher

    An example of a very simple IPCMessageSubscriber connecting to an IPCMessagePublisher.
    This example assumes an already running IPCMessagePublisher.

    IMPORTANT: The below example also assumes the IOLoop is NOT running.

    # Import Tornado libs
    import tornado.ioloop

    # Import Salt libs
    import salt.config
    import salt.transport.ipc

    # Create a new IO Loop.
    # We know that this new IO Loop is not currently running.
    io_loop = tornado.ioloop.IOLoop()

    ipc_publisher_socket_path = '/var/run/ipc_publisher.ipc'

    ipc_subscriber = salt.transport.ipc.IPCMessageSubscriber(ipc_server_socket_path, io_loop=io_loop)

    # Connect to the server
    # Use the associated IO Loop that isn't running.
    io_loop.run_sync(ipc_subscriber.connect)

    # Wait for some data
    package = ipc_subscriber.read_sync()
    '''
    def __init__(self, socket_path, io_loop=None):
        super(IPCMessageSubscriber, self).__init__(
            socket_path, io_loop=io_loop)
        self._read_stream_future = None
        self._saved_data = []
        self._read_in_progress = Lock()

    @tornado.gen.coroutine
    def _read(self, timeout, callback=None):
        try:
            yield self._read_in_progress.acquire(timeout=0.00000001)
        except tornado.gen.TimeoutError:
            raise tornado.gen.Return(None)

        exc_to_raise = None
        ret = None
        try:
            while True:
                if self._read_stream_future is None:
                    self._read_stream_future = self.stream.read_bytes(4096, partial=True)

                if timeout is None:
                    wire_bytes = yield self._read_stream_future
                else:
                    wire_bytes = yield FutureWithTimeout(self.io_loop,
                                                         self._read_stream_future,
                                                         timeout)
                self._read_stream_future = None

                # Remove the timeout once we get some data or an exception
                # occurs. We will assume that the rest of the data is already
                # there or is coming soon if an exception doesn't occur.
                timeout = None

                self.unpacker.feed(wire_bytes)
                first_sync_msg = True
                for framed_msg in self.unpacker:
                    if callback:
                        self.io_loop.spawn_callback(callback, framed_msg['body'])
                    elif first_sync_msg:
                        ret = framed_msg['body']
                        first_sync_msg = False
                    else:
                        self._saved_data.append(framed_msg['body'])
                if not first_sync_msg:
                    # We read at least one piece of data and we're on sync run
                    break
        except TornadoTimeoutError:
            # In the timeout case, just return None.
            # Keep 'self._read_stream_future' alive.
            ret = None
        except StreamClosedError as exc:
            log.trace('Subscriber disconnected from IPC %s', self.socket_path)
            self._read_stream_future = None
            exc_to_raise = exc
        except Exception as exc:
            log.error('Exception occurred in Subscriber while handling stream: %s', exc)
            self._read_stream_future = None
            exc_to_raise = exc

        self._read_in_progress.release()

        if exc_to_raise is not None:
            raise exc_to_raise  # pylint: disable=E0702
        raise tornado.gen.Return(ret)

    def read_sync(self, timeout=None):
        '''
        Read a message from an IPC socket

        The socket must already be connected.
        The associated IO Loop must NOT be running.
        :param int timeout: Timeout when receiving message
        :return: message data if successful. None if timed out. Will raise an
                 exception for all other error conditions.
        '''
        if self._saved_data:
            return self._saved_data.pop(0)
        return self.io_loop.run_sync(lambda: self._read(timeout))

    @tornado.gen.coroutine
    def read_async(self, callback):
        '''
        Asynchronously read messages and invoke a callback when they are ready.

        :param callback: A callback with the received data
        '''
        while not self.connected():
            try:
                yield self.connect(timeout=5)
            except StreamClosedError:
                log.trace('Subscriber closed stream on IPC %s before connect', self.socket_path)
                yield tornado.gen.sleep(1)
            except Exception as exc:
                log.error('Exception occurred while Subscriber connecting: %s', exc)
                yield tornado.gen.sleep(1)
        yield self._read(None, callback)

    def close(self):
        '''
        Routines to handle any cleanup before the instance shuts down.
        Sockets and filehandles should be closed explicitly, to prevent
        leaks.
        '''
        if self._closing:
            return
        super(IPCMessageSubscriber, self).close()
        # This will prevent this message from showing up:
        # '[ERROR   ] Future exception was never retrieved:
        # StreamClosedError'
        if self._read_stream_future is not None and self._read_stream_future.done():
            exc = self._read_stream_future.exception()
            if exc and not isinstance(exc, StreamClosedError):
                log.error("Read future returned exception %r", exc)

    def __del__(self):
        if IPCMessageSubscriber in globals():
            self.close()