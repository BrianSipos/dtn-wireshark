'''
Implementation of a symmetric TCPCL agent.
'''
import datetime
import binascii
import os
import sys
import logging
import argparse
import socket
import ssl
from io import BytesIO
from gi.repository import GLib as glib
import dbus.bus
import dbus.service
from tcpcl import formats, contact, messages, extend


class Config(object):
    ''' Agent configuration.

    .. py:attribute:: enable_test
        A set of test-mode behaviors to enable.
    .. py:attribute:: bus_conn
        The D-Bus connection object to register handlers on.
    .. py:attribute:: stop_on_close
        If True, the agent will stop when all of its contacts are closed.
    .. py:attribute:: ssl_ctx
        An :py:class:`ssl.SSLContext` object configured for this peer.
    .. py:attribute:: require_tls
        If not None, the required negotiated use-TLS state.
    .. py:attribute:: require_host_authn
        If truthy, the peer must have its host name authenticated (by TLS).
    .. py:attribute:: require_node_authn
        If truthy, the peer must have its Node ID authenticated (by TLS).
    .. py:attribute:: nodeid
        The Node ID of this entity, which is a URI.
    .. py:attribute:: keepalive_time
        The desired keepalive time to negotiate.
    .. py:attribute:: idle_time
        The session idle-timeout time.
    '''

    def __init__(self):
        self.enable_test = set()
        self.bus_conn = dbus.bus.BusConnection(dbus.bus.BUS_SESSION)
        self.stop_on_close = False
        self.ssl_ctx = None
        self.require_tls = None
        self.require_host_authn = False
        self.require_node_authn = False
        self.nodeid = u''
        self.keepalive_time = 0
        self.idle_time = 0
        #: Maximum size of RX segments in octets
        self.segment_size_mru = int(10 * (1024 ** 2))
        #: Initial TX segment size
        self.segment_size_tx_initial = int(0.1 * (1024 ** 2))
        #: Target time for dynamic TX segment size
        self.modulate_target_ack_time = None


class Connection(object):
    ''' Optionally secured socket connection.
    This handles octet-level buffering and queuing.

    :param sock: The unsecured socket to wrap.
    :type sock: :py:class:`socket.socket`
    :param as_passive: True if this is the passive side of the connection.
    :type as_passive: bool
    :param peer_name: The name of the socket peer.
    :type peer_name: str
    '''

    def __init__(self, sock, as_passive, peer_name):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._on_close = None
        self._as_passive = as_passive
        self._peer_name = peer_name

        #: Transmit buffer
        self.__tx_buf = b''

        #: The raw socket
        self.__s_notls = None
        #: Optionally secured socket
        self.__s_tls = None

        #: listener for __s_notls socket
        self.__avail_rx_notls_id = None
        self.__avail_tx_notls_id = None
        self.__avail_tx_notls_pend = None
        #: optional listener for __s_tls socket
        self.__avail_rx_tls_id = None
        self.__avail_tx_tls_id = None
        self.__avail_tx_tls_pend = None

        self._replace_socket(sock)

    def is_secure(self):
        ''' Determine if TLS is established.

        :return: True if operating with TLS.
        '''
        return self.__s_tls is not None

    def get_secure_socket(self):
        ''' Get the secure socket object if available.

        :return: The socket object or None.
        '''
        return self.__s_tls

    def __unlisten_notls(self):
        if self.__avail_rx_notls_id is not None:
            glib.source_remove(self.__avail_rx_notls_id)
            self.__avail_rx_notls_id = None
        if self.__avail_tx_notls_id is not None:
            glib.source_remove(self.__avail_tx_notls_id)
            self.__avail_tx_notls_id = None

    def __unlisten_tls(self):
        if self.__avail_rx_tls_id is not None:
            glib.source_remove(self.__avail_rx_tls_id)
            self.__avail_rx_tls_id = None
        if self.__avail_tx_tls_id is not None:
            glib.source_remove(self.__avail_tx_tls_id)
            self.__avail_tx_tls_id = None

    def _replace_socket(self, sock):
        ''' Replace the socket used by this object.
        Any current socket is left open.

        :param sock: The new socket.
        :type sock: :py:class:`socket.socket`
        :return: The old socket.
        '''
        old = self.__s_notls
        self.__unlisten_notls()

        self.__logger.debug('Socket binding on %s', sock)
        self.__s_notls = sock
        if self.__s_notls is not None:
            self.__s_notls.setblocking(0)
            self.__avail_rx_notls_id = glib.io_add_watch(
                self.__s_notls, glib.IO_IN, self._avail_rx_notls)

        return old

    def set_on_close(self, func):
        ''' Set a callback to be run when this connection is closed.

        :param func: The callback, which takes no arguments.
        '''
        self._on_close = func

    def close(self):
        ''' Close the entire connection cleanly.
        '''
        if not self.__s_notls:
            return
        self.__logger.info('Closing connection')

        self.__unlisten_tls()
        self.__unlisten_notls()

        # Best effort to close active socket
        for sock in (self.__s_tls, self.__s_notls):
            if sock is None or sock.fileno() < 0:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except socket.error as err:
                self.__logger.warning('Socket shutdown error: %s', err)
            sock.close()

        self.__s_notls = None
        self.__s_tls = None

        if self._on_close:
            self._on_close()

    def secure(self, ssl_ctx):
        ''' Add a TLS connection layer (if not present).

        :param ssl_ctx: The context to use for security.
        :type ssl_ctx: :py:class:`ssl.SSLContext`
        :raise ssl.SSLError: If the negotiation fails.
        '''
        if self.__s_tls:
            return

        # Pass socket control to TLS
        self.__unlisten_notls()
        self.__s_notls.setblocking(1)

        if self._as_passive:
            s_tls = ssl_ctx.wrap_socket(self.__s_notls,
                                        server_side=True,
                                        do_handshake_on_connect=False)
        else:
            s_tls = ssl_ctx.wrap_socket(self.__s_notls,
                                        server_hostname=self._peer_name,
                                        do_handshake_on_connect=False)

        self.__logger.debug('Socket STARTTLS on %s', s_tls)
        self.__logger.info('Negotiating TLS...')
        s_tls.do_handshake()

        self.__s_tls = s_tls
        self.__logger.info('TLS secured with %s', self.__s_tls.cipher())

        self.__s_tls.setblocking(0)
        self.__avail_rx_tls_id = glib.io_add_watch(
            self.__s_tls, glib.IO_IN, self._avail_rx_tls)

    def unsecure(self):
        ''' Remove any TLS connection layer (if present).
        '''
        if not self.__s_tls:
            return

        self.__logger.debug('Unsecuring TLS...')
        self.__unlisten_tls()

        # Fall-back to old unsecure socket upon failure
        new_notls = self.__s_notls
        self.__unlisten_notls()
        self.__s_notls = None

        # Keep the unsecured socket
        self.__logger.debug('TLS unwrap on %s', self.__s_tls)
        try:
            new_notls = self.__s_tls.unwrap()
        except ssl.SSLError as err:
            self.__logger.warning('Failed to shutdown TLS session: %s', err)
        self.__s_tls = None

        if new_notls.fileno() >= 0:
            self._replace_socket(new_notls)

    def _conn_name(self):
        ''' A name for the connection type. '''
        return 'secure' if self.is_secure() else 'plain'

    #: Size of data stream chunks
    CHUNK_SIZE = 10240
    #: True to log actual hex-encoded data
    DO_DEBUG_DATA = False

    def _avail_rx_notls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`__s_notls` RX data. '''
        if self.__s_tls is not None:
            return True

        return self._rx_proxy(self.__s_notls)

    def _avail_rx_tls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`__s_tls` RX data. '''
        if self.__s_tls is None:
            return True

        return self._rx_proxy(self.__s_tls)

    def _rx_proxy(self, sock):
        ''' Process up to a single CHUNK_SIZE incoming block.

        :return: True if the RX buffer should be pumped more.
        :rtype: bool
        '''
        self.__logger.debug('RX proxy')

        try:
            data = sock.recv(self.CHUNK_SIZE)
        except (socket.error, ssl.SSLWantReadError) as err:
            self.__logger.error('Failed to "recv" on socket: %s', err)
            data = None

        if not data:
            # Connection closed
            self.close()
            return False

        self.__logger.debug('Received %d octets (%s)',
                            len(data), self._conn_name())
        self.recv_raw(data)
        return True

    def recv_raw(self, data):
        ''' Handler for a received block of data.
        Derived classes must overload this method to handle RX data.

        :param data: The received data.
        :type data: str
        '''
        pass

    def _avail_tx_notls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`__s_notls` TX data. '''
        self.__avail_tx_notls_pend = None
        if self.__s_tls is not None or self.__s_notls is None:
            return False

        cont = self._tx_proxy(self.__s_notls)
        if not cont:
            self.__avail_tx_notls_id = None
        return cont

    def _avail_tx_tls(self, *args, **kwargs):
        ''' Callback for new :py:obj:`__s_tls` TX data. '''
        self.__avail_tx_tls_pend = None
        if self.__s_tls is None:
            return False

        cont = self._tx_proxy(self.__s_tls)
        if not cont:
            self.__avail_tx_tls_id = None
        return cont

    def _tx_proxy(self, sock):
        ''' Process up to a single CHUNK_SIZE outgoing block.
        
        :return: True if the TX buffer should be pumped more.
        :rtype: bool
        '''
        # Pull messages into buffer
        if len(self.__tx_buf) < self.CHUNK_SIZE:
            data = self.send_raw(self.CHUNK_SIZE)
            self.__tx_buf += data
            up_empty = (not data)
        else:
            up_empty = False

        # Flush chunks from the buffer
        sent_size = 0
        if self.__tx_buf:
            data = self.__tx_buf[:self.CHUNK_SIZE]
            self.__logger.debug('Sending message %d/%d octets (%s)',
                                len(data), len(self.__tx_buf), self._conn_name())
            try:
                tx_size = sock.send(data)
                self.__logger.debug('Sent %d octets', tx_size)
            except socket.error as err:
                self.__logger.error('Failed to "send" on socket: %s', err)
                tx_size = None

            if tx_size:
                self.__tx_buf = self.__tx_buf[tx_size:]
                sent_size += tx_size
            else:
                # Connection closed
                self.close()
                return False

        buf_empty = (len(self.__tx_buf) == 0)
        if sent_size:
            self.__logger.debug('TX %d octets, remain %d octets (msg empty %s)', sent_size, len(
                self.__tx_buf), up_empty)
        cont = (not buf_empty or not up_empty)
        return cont

    def send_ready(self):
        ''' Called to indicate that :py:meth:`send_raw` will return non-empty.
        This will attempt immediate transmit of chunks if available, and
        queue the rest for later.
        '''
        if self.__s_tls:
            if self.__avail_tx_tls_id is None:
                self.__avail_tx_tls_id = glib.io_add_watch(
                    self.__s_tls, glib.IO_OUT, self._avail_tx_tls)
            if self.__avail_tx_tls_pend is None:
                self.__avail_tx_tls_pend = glib.idle_add(self._avail_tx_tls)

        else:
            if self.__avail_tx_notls_id is None:
                self.__avail_tx_notls_id = glib.io_add_watch(
                    self.__s_notls, glib.IO_OUT, self._avail_tx_notls)
            if self.__avail_tx_notls_pend is None:
                self.__avail_tx_notls_pend = glib.idle_add(
                    self._avail_tx_notls)

    def send_raw(self, size):
        ''' Obtain a block of data to send.
        Derived classes must overload this method to return TX data.

        :param size: The maximum size to obtain.
        :type size: int
        :return: The to-be-transmitted data.
        :rtype: str
        '''
        return b''


class RejectError(Exception):
    ''' Allow recv_* handlers to reject the message.

    :param reason: The rejection reason.
    Should be one of the :py:class:`messages.RejectMsg.Reason` values.
    :type reason: int
    '''

    def __init__(self, reason=None):
        Exception.__init__(self, 'rejected message')
        self.reason = reason


class TerminateError(Exception):
    ''' Allow recv_* handlers to terminate a session.

    :param reason: The termination reason.
    Should be one of the :py:class:`messages.SessionTerm.Reason` values.
    :type reason: int
    '''

    def __init__(self, reason=None):
        Exception.__init__(self, 'terminated session')
        self.reason = reason


class Messenger(Connection):
    ''' Messaging layer of TCPCL.
    This handles message-level buffering and queuing.
    Messages are variable-length individually.

    :param config: The messenger configuration struct.
    :type config: :py:class:`Config`
    :param sock: The (unsecured) connection socket to operate on.
    :type sock: :py:class:`socket.socket`
    '''

    def __init__(self, config, sock, fromaddr=None, toaddr=None):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config

        # agent-configured parmeters
        self._do_send_ack_inter = True
        self._do_send_ack_final = True
        # negotiated parameters
        self._keepalive_time = 0
        self._idle_time = 0
        # scaled segment sizing
        self._send_segment_size_min = int(10 * 1024)
        self._send_segment_size = 0
        self._segment_tx_times = {}
        self._segment_last_ack_len = None
        self._segment_pid_err_last = None
        self._segment_pid_err_accum = None
        # agent timers
        self._keepalive_timer_id = None
        self._idle_timer_id = None

        # Negotiation inputs and states
        self._conhead_peer = None
        self._conhead_this = None
        #: Set after contact negotiation
        self._in_conn = False
        self._sessinit_peer = None
        self._sessinit_this = None
        #: Set after SESS_INIT negotiation
        self._in_sess = False
        self._in_sess_func = None
        #: Set after SESS_TERM sent
        self._in_term = False
        self._in_term_func = None

        self._tls_attempt = False
        # Assume socket is ready
        self._is_open = True

        self._from = fromaddr
        self._to = toaddr
        #: Receive pre-message data buffer
        self.__rx_buf = b''
        #: Transmit post-message data buffer
        self.__tx_buf = b''

        # now set up connection
        if fromaddr:
            as_passive = True
            peer_name = fromaddr[0]
        else:
            as_passive = False
            peer_name = toaddr[0]
        Connection.__init__(self, sock, as_passive, peer_name)

    def is_passive(self):
        ''' Determine if this is the passive side of the session. '''
        return self._from is not None

    def is_sess_idle(self):
        ''' Determine if the session is idle.

        :return: True if there are no data being processed RX or TX side.
        '''
        return len(self.__rx_buf) == 0 and len(self.__tx_buf) == 0

    def set_on_session_start(self, func):
        ''' Set a callback to be run when this session is started.

        :param func: The callback, which takes no arguments.
        '''
        self._in_sess_func = func

    def set_on_session_terminate(self, func):
        ''' Set a callback to be run when this session is terminated.

        :param func: The callback, which takes no arguments.
        '''
        self._in_term_func = func

    def recv_buffer_used(self):
        ''' Get the number of octets waiting in the receive buffer.

        :return: The buffer use (octets).
        :rtype: int.
        '''
        return len(self.__rx_buf)

    def send_buffer_used(self):
        ''' Get the number of octets waiting in the transmit buffer.

        :return: The buffer use (octets).
        :rtype: int.
        '''
        return len(self.__tx_buf)

    def send_buffer_decreased(self, buf_use):
        ''' A handler function to be used when message buffer data is
        transmitted.

        :param buf_use: The current buffer use (octets).
        :type buf_use: int
        '''
        pass

    def close(self):
        self._idle_stop()
        self._keepalive_stop()
        super(Messenger, self).close()

    def _keepalive_stop(self):
        ''' Inhibit keepalive timer. '''
        if self._keepalive_timer_id is not None:
            glib.source_remove(self._keepalive_timer_id)
            self._keepalive_timer_id = None

    def _keepalive_reset(self):
        ''' Reset keepalive timer upon TX. '''
        self._keepalive_stop()
        if self._keepalive_time > 0:
            self._keepalive_timer_id = glib.timeout_add(
                int(self._keepalive_time * 1e3), self._keepalive_timeout)

    def _keepalive_timeout(self):
        ''' Handle TX keepalive. '''
        self.__logger.debug('Keepalive time')
        self.send_message(messages.MessageHead() / messages.Keepalive())

    def _idle_stop(self):
        ''' Inhibit the idle timer. '''
        if self._idle_timer_id is not None:
            glib.source_remove(self._idle_timer_id)
            self._idle_timer_id = None

    def _idle_reset(self):
        ''' Reset the idle timer upon TX or RX. '''
        self._idle_stop()
        if self._idle_time > 0:
            self._idle_timer_id = glib.timeout_add(
                int(self._idle_time * 1e3), self._idle_timeout)

    def _idle_timeout(self):
        ''' Handle an idle timer timeout. '''
        self._idle_stop()
        self.__logger.debug('Idle time reached')
        self.send_sess_term(messages.SessionTerm.Reason.IDLE_TIMEOUT, False)
        return False

    def recv_raw(self, data):
        ''' Attempt to extract a message from the current read buffer.
        '''
        self._idle_reset()
        # always append
        self.__rx_buf += data
        self.__logger.debug('RX buffer size %d octets', len(self.__rx_buf))

        # Handle as many messages as are present
        while self.__rx_buf:
            if self._in_conn:
                msgcls = messages.MessageHead
            else:
                msgcls = contact.Head

            # Probe for full message (by reading back encoded data)
            try:
                pkt = msgcls(self.__rx_buf)
                pkt_data = bytes(pkt)
            except formats.VerifyError as err:
                self.__logger.debug('Decoded partial packet: %s', err)
                return
            except Exception as err:
                self.__logger.error('Failed to decode packet: %s', err)
                raise
            if self.DO_DEBUG_DATA:
                self.__logger.debug('RX packet data: %s',
                                    binascii.hexlify(pkt_data))
            self.__logger.debug('Matched message %d octets', len(pkt_data))

            # Keep final padding as future data
            self.__rx_buf = self.__rx_buf[len(pkt_data):]
            self.__logger.debug('RX remain %d octets', len(self.__rx_buf))

            self.recv_message(pkt)

    def recv_message(self, pkt):
        ''' Handle a received full message (or contact header).

        :param pkt: The message packet received.
        '''
        self.__logger.info('RX: %s', repr(pkt))

        if isinstance(pkt, contact.Head):
            if pkt.magic != contact.MAGIC_HEAD:
                raise ValueError('Contact header with bad magic: {0}'.format(
                    binascii.hexlify(pkt.magic)))
            if pkt.version != 4:
                raise ValueError(
                    'Contact header with bad version: {0}'.format(pkt.version))

            if self._as_passive:
                # After initial validation send reply
                self._conhead_this = self.send_contact_header().payload

            self._conhead_peer = pkt.payload
            self.merge_contact_params()
            self._in_conn = True

            # Check policy before attempt
            if self._config.require_tls is not None:
                if self._tls_attempt != self._config.require_tls:
                    self.__logger.error('TLS parameter violated policy')
                    self.close()
                    return

            # Both sides immediately try TLS, Client initiates handshake
            if self._tls_attempt:
                # flush the buffers ahead of TLS
                while self.__tx_buf:
                    self._avail_tx_notls()

                # Either case, TLS handshake begins
                try:
                    self.secure(self._config.ssl_ctx)
                except ssl.SSLError as err:
                    self.__logger.error('TLS failed: %s', err)
                    self.close()
                    return

            # Check policy after attempt
            if self._config.require_tls is not None:
                if self.is_secure() != self._config.require_tls:
                    self.__logger.error('TLS result violated policy')
                    self.close()
                    return

            # Contact negotiation is completed, begin session negotiation
            if not self._as_passive:
                # Passive side listens first
                self._sessinit_this = self.send_sess_init().payload

        else:
            # Some payloads are empty and scapy will not construct them
            msgcls = pkt.guess_payload_class(b'')

            try:  # Allow rejection from any of these via RejectError
                if msgcls == messages.SessionInit:
                    if self._as_passive:
                        # After initial validation send reply
                        self._sessinit_this = self.send_sess_init().payload

                    self._sessinit_peer = pkt.payload
                    self._in_sess = True
                    self.merge_session_params()
                    if self._in_sess_func:
                        self._in_sess_func()

                elif msgcls == messages.SessionTerm:
                    # Send a reply (if not the initiator)
                    if not self._in_term:
                        self.send_sess_term(pkt.payload.reason, True)

                    self.recv_sess_term(pkt.payload.reason)

                elif msgcls in (messages.Keepalive, messages.RejectMsg):
                    # No need to respond at this level
                    pass

                # Delegated handlers
                elif msgcls == messages.TransferSegment:
                    self.recv_xfer_data(
                        transfer_id=pkt.payload.transfer_id,
                        flags=pkt.getfieldval('flags'),
                        data=pkt.payload.getfieldval('data'),
                        ext_items=pkt.ext_items
                    )
                elif msgcls == messages.TransferAck:
                    self.recv_xfer_ack(
                        transfer_id=pkt.payload.transfer_id,
                        flags=pkt.getfieldval('flags'),
                        length=pkt.payload.length
                    )
                elif msgcls == messages.TransferRefuse:
                    self.recv_xfer_refuse(pkt.payload.transfer_id, pkt.flags)

                else:
                    # Bad RX message
                    raise RejectError(messages.RejectMsg.Reason.UNKNOWN)

            except RejectError as err:
                self.send_reject(err.reason, pkt)
            except TerminateError as err:
                self.send_sess_term(err.reason, False)

    def send_contact_header(self):
        ''' Send the initial Contact Header non-message.
        Parameters are based on current configuration.
        '''
        flags = 0
        if self._config.ssl_ctx:
            flags |= contact.ContactV4.Flag.CAN_TLS

        options = dict(
            flags=flags,
        )

        pkt = contact.Head() / contact.ContactV4(**options)
        self.send_message(pkt)
        return pkt

    def merge_contact_params(self):
        ''' Combine local and peer contact headers to contact configuration.
        '''
        self.__logger.debug('Contact negotiation')

        this_can_tls = (self._conhead_this.flags &
                        contact.ContactV4.Flag.CAN_TLS)
        peer_can_tls = (self._conhead_peer.flags &
                        contact.ContactV4.Flag.CAN_TLS)
        self._tls_attempt = (this_can_tls and peer_can_tls)

    def send_sess_init(self):
        ''' Send the initial SESS_INIT message.
        Parameters are based on current configuration.
        '''
        ext_items = []
        if 'private_extensions' in self._config.enable_test:
            ext_items.append(messages.SessionExtendHeader(flags=messages.SessionExtendHeader.Flag.CRITICAL) / extend.SessionPrivateDummy())
        options = dict(
            keepalive=self._config.keepalive_time,
            segment_mru=self._config.segment_size_mru,
            nodeid_data=self._config.nodeid,
            ext_items=ext_items,
        )
        pkt = messages.MessageHead() / messages.SessionInit(**options)
        self.send_message(pkt)
        return pkt

    def merge_session_params(self):
        ''' Combine local and peer SESS_INIT parameters.

        :raise TerminateError: If there is some failure to negotiate.
        '''
        self.__logger.debug('Session negotiation')

        if self.get_secure_socket():
            # Verify TLS name bindings
            cert = self.get_secure_socket().getpeercert()

            # DNS/IP matching with standard function to handle wildcards
            if self._as_passive:
                (hostname, aliaslist, _) = socket.gethostbyaddr(self._peer_name)
                peer_names = [self._peer_name, hostname] + list(aliaslist)
            else:
                peer_names = [self._peer_name]
            host_authn = None
            if cert and peer_names:
                self.__logger.debug('Authenticating TLS host "%s" with subjectAltName: %s',
                                    peer_names, cert.get('subjectAltName'))
                for peer_name in peer_names:
                    try:
                        ssl.match_hostname(cert, peer_name)
                        host_authn = peer_name
                        break
                    except ssl.CertificateError:
                        pass
            # host authentication result
            if host_authn:
                self.__logger.debug('Certificate matched host name "%s"', host_authn)
            else:
                self.__logger.warning('Peer host name not authenticated')
                if self._config.require_host_authn:
                    raise TerminateError(messages.SessionTerm.Reason.CONTACT_FAILURE)

            # Exact Node ID URI matching
            node_id = self._sessinit_peer.nodeid_data
            node_authn = None
            if cert and node_id:
                self.__logger.debug('Authenticating Node ID "%s" with subjectAltName: %s',
                                    node_id, cert.get('subjectAltName'))
                uri_names = set()
                for (name_type, name_data) in cert.get('subjectAltName', []):
                    if name_type == 'URI':
                        uri_names.add(name_data)
                if node_id in uri_names:
                    node_authn = node_id
            # node authentication result
            if node_authn:
                self.__logger.debug('Certificate matched Node ID "%s"', node_authn)
            else:
                self.__logger.warning('Peer Node ID not authenticated')
                if self._config.require_node_authn:
                    raise TerminateError(messages.SessionTerm.Reason.CONTACT_FAILURE)

        self._keepalive_time = min(self._sessinit_this.keepalive,
                                   self._sessinit_peer.keepalive)
        self.__logger.debug('KEEPALIVE time %d', self._keepalive_time)
        self._idle_time = self._config.idle_time
        self._keepalive_reset()
        self._idle_reset()

        # Start at a smaller initial and scale as appropriate
        self._send_segment_size = min(
            self._config.segment_size_tx_initial,
            self._sessinit_peer.segment_mru
        )
        self._segment_tx_times = {}
        self._segment_last_ack_len = 0
        self._segment_pid_err_last = None
        self._segment_pid_err_accum = 0

    def _modulate_tx_seg_size(self, delta_b, delta_t):
        ''' Scale the TX segment size to achieve a round-trip ACK timing goal.
        '''
        target_size = self._config.modulate_target_ack_time * \
            (delta_b / delta_t)
        error_size = self._send_segment_size - target_size

        # Discrete derivative
        if self._segment_pid_err_last is None:
            error_delta = 0
        else:
            error_delta = error_size - self._segment_pid_err_last
        self._segment_pid_err_last = error_size
        # Discrete integrate
        error_accum = self._segment_pid_err_accum
        self._segment_pid_err_accum += error_size

        # PD control
        next_seg_size = int(
            self._send_segment_size
            -2e-1 * error_size
            +6e-2 * error_delta
            -1e-4 * error_accum
        )

        # Clamp control to the limits
        self._send_segment_size = min(
            max(
                next_seg_size,
                self._send_segment_size_min
            ),
            self._sessinit_peer.segment_mru
        )

    def send_raw(self, size):
        ''' Pop some data from the TX queue.

        :param size: The maximum size to pop from the queue.
        :return: The chunk of data popped from the queue.
        :rtype: bytes
        '''
        data = self.__tx_buf[:size]
        if data:
            self.__logger.debug('TX popping %d of %d',
                                len(data), len(self.__tx_buf))
        self.__tx_buf = self.__tx_buf[len(data):]

        self.send_buffer_decreased(len(self.__tx_buf))
        return data

    def send_message(self, pkt):
        ''' Send a full message (or contact header).

        :param pkt: The message packet to send.
        '''
        self.__logger.info('TX: %s', repr(pkt))
        pkt_data = bytes(pkt)
        if self.DO_DEBUG_DATA:
            self.__logger.debug('TX packet data: %s',
                                binascii.hexlify(pkt_data))

        self.__tx_buf += pkt_data
        self.send_ready()

        self._keepalive_reset()
        self._idle_reset()

    def send_reject(self, reason, pkt=None):
        ''' Send a message rejection response.

        :param reason: The reject reason code.
        :type reason: int
        :param pkt: The message being rejected (optional).
        :type pkt: The orignal :py:class:`MessageHead` packet.
        '''
        rej_load = messages.RejectMsg(reason=reason)
        if pkt is not None:
            rej_load.rej_msg_id = pkt.msg_id
        self.send_message(messages.MessageHead() / rej_load)

    def send_sess_term(self, reason, is_reply):
        ''' Send the SESS_TERM message.
        After calling this method no further transfers can be started.
        '''
        if not self._in_sess:
            raise RuntimeError('Cannot terminate while not in session')
        if self._in_term:
            raise RuntimeError('Already in terminating state')

        self._in_term = True
        if self._in_term_func:
            self._in_term_func()

        flags = 0
        if is_reply:
            flags |= messages.SessionTerm.Flag.REPLY

        options = dict(
            flags=flags,
            reason=reason,
        )
        self.send_message(messages.MessageHead() /
                          messages.SessionTerm(**options))

    def start(self):
        ''' Main state machine of the agent contact. '''
        self._conhead_peer = None
        self._conhead_this = None
        self._in_conn = False
        self._sessinit_peer = None
        self._sessinit_this = None
        self._in_sess = False
        self._in_term = False

        if not self._as_passive:
            # Passive side listens first
            self._conhead_this = self.send_contact_header().payload

    def recv_sess_term(self, reason):
        ''' Handle reception of SESS_TERM message.

        :param reason: The termination reason.
        :type reason: int
        '''
        if not self._in_sess:
            raise RejectError(messages.RejectMsg.Reason.UNEXPECTED)

    def recv_xfer_data(self, transfer_id, flags, data, ext_items):
        ''' Handle reception of XFER_DATA message.

        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param flags: The transfer flags.
        :type flags: int
        :param data: The segment data.
        :type data: str
        :param ext_items: Extension items which may be in the start segment.
        :type ext_items: array
        '''
        self.__logger.debug('XFER_DATA %d %s', transfer_id, flags)
        if not self._in_sess:
            raise RejectError(messages.RejectMsg.Reason.UNEXPECTED)

    def recv_xfer_ack(self, transfer_id, flags, length):
        ''' Handle reception of XFER_ACK message.

        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param flags: The transfer flags.
        :type flags: int
        :param length: The acknowledged length.
        :type length: int
        '''
        self.__logger.debug('XFER_ACK %d %s %s', transfer_id, flags, length)
        if not self._in_sess:
            raise RejectError(messages.RejectMsg.Reason.UNEXPECTED)

    def recv_xfer_refuse(self, transfer_id, reason):
        ''' Handle reception of XFER_REFUSE message.

        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param reason: The refusal reason code.
        :type reason: int
        '''
        self.__logger.debug('XFER_REFUSE %d %s', transfer_id, reason)
        if not self._in_sess:
            raise RejectError(messages.RejectMsg.Reason.UNEXPECTED)

    def send_xfer_data(self, transfer_id, data, flg, ext_items=None):
        ''' Send a XFER_DATA message.

        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param data: The segment data.
        :type data: str
        :param flg: Data flags for :py:class:`TransferSegment`
        :type flg: int
        :param ext_items: Extension items for the starting segment only.
        :type ext_items: list or None
        '''
        if not self._in_sess:
            raise RuntimeError(
                'Attempt to transfer before session established')
        if ext_items and not flg & messages.TransferSegment.Flag.START:
            raise RuntimeError(
                'Cannot send extension items outside of START message')
        if ext_items is None:
            ext_items = []

        self.send_message(messages.MessageHead() /
                          messages.TransferSegment(transfer_id=transfer_id,
                                                   flags=flg,
                                                   data=data,
                                                   ext_items=ext_items))

    def send_xfer_ack(self, transfer_id, length, flg):
        ''' Send a XFER_ACK message.

        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param length: The acknowledged length.
        :type length: int
        :param flg: Data flags for :py:class:`TransferAck`
        :type flg: int
        '''
        if not self._in_sess:
            raise RuntimeError(
                'Attempt to transfer before session established')

        self.send_message(messages.MessageHead() /
                          messages.TransferAck(transfer_id=transfer_id,
                                               flags=flg,
                                               length=length))

    def send_xfer_refuse(self, transfer_id, reason):
        ''' Send a XFER_REFUSE message.

        :param transfer_id: The bundle ID number.
        :type transfer_id: int
        :param reason: The refusal reason code.
        :type reason: int
        '''
        if not self._in_sess:
            raise RuntimeError(
                'Attempt to transfer before session established')

        self.send_message(messages.MessageHead() /
                          messages.TransferRefuse(transfer_id=transfer_id,
                                                  flags=reason))


class BundleItem(object):
    ''' State for RX and TX full bundles.

    .. py:attribute:: transfer_id The unique transfer ID number.
    .. py:attribute:: total_length The length from the file (sender) or
        known from the Transfer Length extension (receiver)
    .. py:attribute:: ack_length The total acknowledged length.
    '''

    def __init__(self):
        self.transfer_id = None
        self.total_length = None
        self.ack_length = 0
        self.file = None


class ContactHandler(Messenger, dbus.service.Object):
    ''' A bus interface to the contact message handler.

    :param hdl_kwargs: Arguments to :py:class:`Messenger` constructor.
    :type hdl_kwargs: dict
    :param bus_kwargs: Arguments to :py:class:`dbus.service.Object` constructor.
    :type bus_kwargs: dict
    '''

    #: D-Bus interface name
    DBUS_IFACE = 'org.ietf.dtn.tcpcl.Contact'

    def __init__(self, hdl_kwargs, bus_kwargs):
        self.__logger = logging.getLogger(self.__class__.__name__)
        Messenger.__init__(self, **hdl_kwargs)
        dbus.service.Object.__init__(self, **bus_kwargs)
        self.object_path = bus_kwargs['object_path']
        # Transmit state
        #: Next sequential bundle ID
        self._tx_next_id = 1
        #: TX bundles pending start (as BundleItem) in queue order
        self._tx_pend_start = []
        #: TX bundles pending full ACK (as BundleItem)
        self._tx_pend_ack = set()
        #: Names of pending TX bundles in _tx_pend_start and _tx_pend_ack
        self._tx_map = {}
        #: Active TX bundle
        self._tx_tmp = None
        #: Accumulated TX length
        self._tx_length = None
        self._process_queue_pend = None

        # Receive state
        #: Active RX bundle
        self._rx_tmp = None
        #: Full RX bundles pending delivery (as BundleItem)
        self._rx_bundles = []
        #: Names of pending RX bundles
        self._rx_map = {}

    def next_id(self):
        ''' Get the next available bundle ID number.

        :return: A valid bundle ID.
        :rtype: int
        '''
        bid = self._tx_next_id
        self._tx_next_id += 1
        return bid

    def _rx_setup(self, transfer_id, total_length):
        ''' Begin reception of a transfer. '''
        self._rx_tmp = BundleItem()
        self._rx_tmp.transfer_id = transfer_id
        self._rx_tmp.file = BytesIO()
        self._rx_tmp.total_length = total_length  # may be None

        self.recv_bundle_started(str(transfer_id), dbus.String(
        ) if total_length is None else total_length)

    def _rx_teardown(self):
        self._rx_tmp = None

    def _check_sess_term(self):
        ''' Perform post-termination logic. '''
        if self._in_term and self.is_sess_idle():
            self.__logger.info('Closing in terminating state')
            self.close()

    def recv_sess_term(self, reason):
        Messenger.recv_sess_term(self, reason)

        # No further processing
        while self._tx_pend_start:
            item = self._tx_pend_start.pop(0)
            self.__logger.warning('Terminating and ignoring transfer %d', item.transfer_id)
            self.send_bundle_finished(
                str(item.transfer_id),
                item.total_length or 0,
                'session terminating'
            )
        self._check_sess_term()

    def recv_xfer_data(self, transfer_id, flags, data, ext_items):
        Messenger.recv_xfer_data(self, transfer_id, flags, data, ext_items)

        if flags & messages.TransferSegment.Flag.START:
            self._rx_setup(transfer_id, None)

        elif self._rx_tmp is None or self._rx_tmp.transfer_id != transfer_id:
            # Each ID in sequence after start must be identical
            raise RejectError(messages.RejectMsg.Reason.UNEXPECTED)

        self._rx_tmp.file.write(data)
        recv_length = self._rx_tmp.file.tell()

        if flags & messages.TransferSegment.Flag.END:
            if self._do_send_ack_final:
                self.send_xfer_ack(transfer_id, recv_length, flags)

            item = self._rx_tmp
            self._rx_bundles.append(item)
            self._rx_map[item.transfer_id] = item

            self.__logger.info('Finished RX size %d', recv_length)
            self.recv_bundle_finished(
                str(item.transfer_id), recv_length, 'success')
            self._rx_teardown()

            self._check_sess_term()
        else:
            if self._do_send_ack_inter:
                self.send_xfer_ack(transfer_id, recv_length, flags)
                self.recv_bundle_intermediate(
                    str(self._rx_tmp.transfer_id), recv_length)

    def recv_xfer_ack(self, transfer_id, flags, length):
        Messenger.recv_xfer_ack(self, transfer_id, flags, length)

        if self._config.modulate_target_ack_time is not None:
            delta_b = length - self._segment_last_ack_len
            self._segment_last_ack_len = length

            rx_time = datetime.datetime.utcnow()
            tx_time = self._segment_tx_times.pop(length)
            delta_t = (rx_time - tx_time).total_seconds()

            self._modulate_tx_seg_size(delta_b, delta_t)

        item = self._tx_map[transfer_id]
        item.ack_length = length
        if flags & messages.TransferSegment.Flag.END:
            if not self._do_send_ack_final:
                raise RejectError(messages.RejectMsg.Reason.UNEXPECTED)

            self.send_bundle_finished(str(item.transfer_id), length, 'success')
            self._tx_pend_ack.remove(item)
            self._tx_map.pop(transfer_id)
            self._check_sess_term()
        else:
            if not self._do_send_ack_inter:
                raise RejectError(messages.RejectMsg.Reason.UNEXPECTED)
            self.send_bundle_intermediate(str(item.transfer_id), length)

    def recv_xfer_refuse(self, transfer_id, reason):
        Messenger.recv_xfer_refuse(self, transfer_id, reason)

        self.send_bundle_finished(transfer_id, 'refused with code %s', reason)
        item = self._tx_map.pop(transfer_id)
        self._tx_pend_ack.remove(item)

        # interrupt in-progress
        if self._tx_tmp is not None and self._tx_tmp.transfer_id == transfer_id:
            self._tx_teardown()

        self._check_sess_term()

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='b')
    def is_secure(self):
        return Connection.is_secure(self)

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='b')
    def is_sess_idle(self):
        return (
            Messenger.is_sess_idle(self)
            and self._rx_tmp is None
            and self._tx_tmp is None
            and not self._tx_pend_start
            and not self._tx_pend_ack
        )

    @dbus.service.method(DBUS_IFACE, in_signature='y', out_signature='')
    def terminate(self, reason_code=None):
        ''' Perform the termination procedure.

        :param reason_code: The termination reason.
        Should be one of the :py:class:`messages.SessionTerm.Reason` values.
        :type reason_code: int or None
        '''
        if reason_code is None:
            reason_code = messages.SessionTerm.Reason.UNKNOWN
        self.send_sess_term(reason_code, False)

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='')
    def close(self):
        ''' Close the TCP connection immediately. '''
        if tuple(self.locations):
            self.remove_from_connection()

        Messenger.close(self)

    def send_bundle_fileobj(self, file):
        ''' Send bundle from a file-like object.

        :param file: The file to send.
        :type file: file-like
        :return: The new transfer ID.
        :rtype: int
        '''
        item = BundleItem()
        item.file = file
        return self._add_queue_item(item)

    @dbus.service.method(DBUS_IFACE, in_signature='ay', out_signature='s')
    def send_bundle_data(self, data):
        ''' Send bundle data directly.
        '''

        # byte array to str
        data = b''.join([chr(val) for val in data])

        item = BundleItem()
        item.file = BytesIO(data)
        return str(self._add_queue_item(item))

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='s')
    def send_bundle_file(self, filepath):
        ''' Send a bundle from the filesystem.
        '''
        item = BundleItem()
        item.file = open(filepath, 'rb')
        return str(self._add_queue_item(item))

    def _add_queue_item(self, item):
        if item.transfer_id is None:
            item.transfer_id = self.next_id()

        self._tx_pend_start.append(item)
        self._tx_map[item.transfer_id] = item

        self._process_queue_trigger()
        return item.transfer_id

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='as')
    def send_bundle_get_queue(self):
        return dbus.Array([str(bid) for bid in self._tx_map.keys()])

    @dbus.service.signal(DBUS_IFACE, signature='st')
    def send_bundle_started(self, bid, length):
        pass

    @dbus.service.signal(DBUS_IFACE, signature='st')
    def send_bundle_intermediate(self, bid, length):
        pass

    @dbus.service.signal(DBUS_IFACE, signature='sts')
    def send_bundle_finished(self, bid, length, result):
        pass

    @dbus.service.signal(DBUS_IFACE, signature='sv')
    def recv_bundle_started(self, bid, length):
        pass

    @dbus.service.signal(DBUS_IFACE, signature='st')
    def recv_bundle_intermediate(self, bid, length):
        pass

    @dbus.service.signal(DBUS_IFACE, signature='sts')
    def recv_bundle_finished(self, bid, length, result):
        pass

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='as')
    def recv_bundle_get_queue(self):
        return dbus.Array([str(bid) for bid in self._rx_map.keys()])

    @dbus.service.method(DBUS_IFACE, in_signature='s', out_signature='ay')
    def recv_bundle_pop_data(self, bid):
        bid = int(bid)
        item = self._rx_map.pop(bid)
        self._rx_bundles.remove(item)
        item.file.seek(0)
        return item.file.read()

    @dbus.service.method(DBUS_IFACE, in_signature='ss', out_signature='')
    def recv_bundle_pop_file(self, bid, filepath):
        bid = int(bid)
        item = self._rx_map.pop(bid)
        self._rx_bundles.remove(item)
        item.file.seek(0)

        import shutil
        out_file = open(filepath, 'wb')
        shutil.copyfileobj(item.file, out_file)

    def send_buffer_decreased(self, buf_use):
        if self._send_segment_size is None:
            return

        # heuristic for when to attempt to put new segments in
        if buf_use < 5 * self._send_segment_size:
            self._process_queue_trigger()

    def _tx_teardown(self):
        ''' Clear the TX in-progress bundle state. '''
        self._tx_tmp = None
        self._tx_length = None
        self._process_queue_trigger()

    def _process_queue_trigger(self):
        if self._process_queue_pend is None:
            self._process_queue_pend = glib.idle_add(self._process_queue)

    def _process_queue(self):
        ''' Perform the next TX segment if possible.
        Only a single transfer is handled at a time to avoid blocking the
        socket processing event loop.

        :return: True to continue processing at a later time.
        :rtype: bool
        '''
        self._process_queue_pend = None
        self.__logger.debug('Processing queue of %d items',
                            len(self._tx_pend_start))

        # work from the head of the list
        if self._tx_tmp is None:
            if not self._in_sess:
                # waiting for session
                return True
            if not self._tx_pend_start:
                # nothing to do
                return False

            self._tx_tmp = self._tx_pend_start.pop(0)

            self._tx_tmp.file.seek(0, os.SEEK_END)
            self._tx_tmp.total_length = self._tx_tmp.file.tell()
            self._tx_tmp.file.seek(0)
            self._tx_length = 0

            self.send_bundle_started(
                str(self._tx_tmp.transfer_id),
                self._tx_tmp.total_length
            )

        if self._tx_length == self._tx_tmp.total_length:
            # Nothing more to send, just waiting on ACK
            return False

        # send next segment
        flg = 0
        ext_items = []
        if 'private_extensions' in self._config.enable_test:
            ext_items.append(messages.TransferExtendHeader(flags=messages.SessionExtendHeader.Flag.CRITICAL) / extend.TransferPrivateDummy())
        if self._tx_length == 0:
            flg |= messages.TransferSegment.Flag.START
            ext_items.append(
                messages.TransferExtendHeader() / extend.TransferTotalLength(total_length=self._tx_tmp.total_length)
            )
        data = self._tx_tmp.file.read(self._send_segment_size)
        self._tx_length += len(data)
        if self._tx_length == self._tx_tmp.total_length:
            flg |= messages.TransferSegment.Flag.END

        # Actual segment
        self.send_xfer_data(self._tx_tmp.transfer_id, data, flg, ext_items)
        # Mark the transmit time
        self._segment_tx_times[self._tx_length] = datetime.datetime.utcnow()

        if flg & messages.TransferSegment.Flag.END:
            if not self._do_send_ack_final:
                self.send_bundle_finished(
                    str(self._tx_tmp.transfer_id),
                    self._tx_tmp.file.tell(),
                    'unacknowledged'
                )
                self._tx_map.pop(self._tx_tmp.transfer_id)
            # done sending segments but will not yet be fully acknowledged
            self._tx_pend_ack.add(self._tx_tmp)
            self._tx_teardown()

        return False


class Agent(dbus.service.Object):
    ''' Overall agent behavior.

    :param config: The agent configuration object.
    :type config: :py:class:`Config`
    :param bus_kwargs: Arguments to :py:class:`dbus.service.Object` constructor.
        If not provided the default dbus configuration is used.
    :type bus_kwargs: dict or None
    '''

    DBUS_IFACE = 'org.ietf.dtn.tcpcl.Agent'

    def __init__(self, config, bus_kwargs=None):
        self.__logger = logging.getLogger(self.__class__.__name__)
        self._config = config
        self._on_stop = None
        #: Set when shutdown() is called and waiting on sessions
        self._in_shutdown = False

        self._bindsocks = {}
        self._obj_id = 0
        self._handlers = []
        self._path_to_handler = {}

        if bus_kwargs is None:
            bus_kwargs = dict(
                conn=config.bus_conn,
                object_path='/org/ietf/dtn/tcpcl/Agent'
            )
        dbus.service.Object.__init__(self, **bus_kwargs)

    def __del__(self):
        self.stop()

    def _get_obj_path(self):
        hdl_id = self._obj_id
        self._obj_id += 1
        return '/org/ietf/dtn/tcpcl/Contact{0}'.format(hdl_id)

    def _bind_handler(self, **kwargs):
        if not self._config.bus_conn:
            return

        path = self._get_obj_path()
        hdl = ContactHandler(
            hdl_kwargs=kwargs,
            bus_kwargs=dict(conn=self._config.bus_conn, object_path=path)
        )

        self._handlers.append(hdl)
        self._path_to_handler[path] = hdl
        hdl.set_on_close(lambda: self._unbind_handler(hdl))

        self.connection_opened(path)
        return hdl

    def _unbind_handler(self, hdl):
        path = hdl.object_path
        self.connection_closed(path)
        self._path_to_handler.pop(path)
        self._handlers.remove(hdl)

        if not self._handlers and self._config.stop_on_close:
            self.stop()

    def set_on_stop(self, func):
        ''' Set a callback to be run when this agent is stopped.

        :param func: The callback, which takes no arguments.
        '''
        self._on_stop = func

    @dbus.service.signal(DBUS_IFACE, signature='o')
    def connection_opened(self, objpath):
        ''' Emitted when a connection is opened. '''
        self.__logger.info('Opened handler at "%s"', objpath)

    @dbus.service.signal(DBUS_IFACE, signature='o')
    def connection_closed(self, objpath):
        ''' Emitted when a connection is closed. '''
        self.__logger.info('Closed handler at "%s"', objpath)

    @dbus.service.method(DBUS_IFACE, in_signature='', out_signature='b')
    def shutdown(self):
        ''' Gracefully terminate all open sessions.
        Once the sessions are closed then the agent may stop.

        :return: True if the agent is stopped immediately or
            False if a wait is needed.
        '''
        self.__logger.info('Shutting down agent')
        self._in_shutdown = True
        if not self._handlers:
            self.stop()
            return True

        for hdl in self._handlers:
            hdl.terminate()
        self.__logger.info('Waiting on sessions to terminate')
        return False

    @dbus.service.method(DBUS_IFACE, in_signature='')
    def stop(self):
        ''' Immediately stop the agent and disconnect any sessions. '''
        for spec in tuple(self._bindsocks.keys()):
            self.listen_stop(*spec)

        for hdl in self._handlers:
            hdl.close()

        if tuple(self.locations):
            self.remove_from_connection()

        if self._on_stop:
            self._on_stop()

    @dbus.service.method(DBUS_IFACE, in_signature='si')
    def listen(self, address, port):
        ''' Begin listening for incoming connections and defer handling
        connections to `glib` event loop.
        '''
        bindspec = (address, port)
        if bindspec in self._bindsocks:
            raise dbus.DBusException('Already listening')

        sock = socket.socket(socket.AF_INET)
        sock.bind(bindspec)

        self.__logger.info('Listening on %s:%d', address or '*', port)
        sock.listen(1)
        self._bindsocks[bindspec] = sock
        glib.io_add_watch(sock, glib.IO_IN, self._accept)

    @dbus.service.method(DBUS_IFACE, in_signature='si')
    def listen_stop(self, address, port):
        ''' Stop listening for connections on an existing port binding.
        '''
        bindspec = (address, port)
        if bindspec not in self._bindsocks:
            raise dbus.DBusException('Not listening')

        sock = self._bindsocks.pop(bindspec)
        self.__logger.info('Un-listening on %s:%d', address or '*', port)
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except socket.error as err:
            self.__logger.warning('Bind socket shutdown error: %s', err)
        sock.close()

    def _accept(self, bindsock, *_args, **_kwargs):
        ''' Callback to handle incoming connections.

        :return: True to continue listening.
        '''
        newsock, fromaddr = bindsock.accept()
        self.__logger.info('Connecting')
        hdl = self._bind_handler(
            config=self._config, sock=newsock, fromaddr=fromaddr)

        try:
            hdl.start()
        except Exception as err:
            self.__logger.warning('Failed: %s', err)

        return True

    @dbus.service.method(DBUS_IFACE, in_signature='si', out_signature='o')
    def connect(self, address, port):
        ''' Initiate an outgoing connection and defer handling state to
        `glib` event loop.

        :return: The new contact object path.
        :rtype: str
        '''
        self.__logger.info('Connecting')
        sock = socket.socket(socket.AF_INET)
        sock.connect((address, port))

        hdl = self._bind_handler(
            config=self._config, sock=sock, toaddr=(address, port))
        hdl.start()

        return hdl.object_path

    def handler_for_path(self, path):
        ''' Look up a contact by its object path.
        '''
        return self._path_to_handler[path]

    def exec_loop(self):
        ''' Run this agent in an event loop.
        The on_stop callback is replaced to quit the event loop.
        '''
        eloop = glib.MainLoop()
        self.set_on_stop(lambda: eloop.quit())
        try:
            eloop.run()
        except KeyboardInterrupt:
            if not self.shutdown():
                # wait for graceful shutdown
                eloop.run()


def str2bool(val):
    ''' Require an option value to be boolean text.
    '''
    if val.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif val.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected')


def uristr(val):
    ''' Require an option value to be a URI.
    '''
    from urllib.parse import urlparse

    nodeid_uri = urlparse(val)
    if not nodeid_uri.scheme:
        raise argparse.ArgumentTypeError('URI value expected')
    return val


def main(*argv):
    from dbus.mainloop.glib import DBusGMainLoop

    parser = argparse.ArgumentParser(argv[0])
    parser.add_argument('--log-level', dest='log_level', default='info',
                        metavar='LEVEL',
                        help='Console logging lowest level displayed.')
    subp = parser.add_subparsers(dest='action', help='action')
    parser.add_argument('--nodeid', type=uristr,
                        help='This entity\'s Node ID')
    parser.add_argument('--keepalive', type=int,
                        help='Keepalive time in seconds')
    parser.add_argument('--idle', type=int,
                        help='Idle time in seconds')
    parser.add_argument('--bus-service', type=str,
                        help='D-Bus service name')
    parser.add_argument('--tls-disable', dest='tls_enable', default=True, action='store_false',
                        help='Disallow use of TLS on this endpoint')
    parser.add_argument('--tls-version', type=str,
                        help='Version name of TLS to use')
    parser.add_argument('--tls-require', default=None, type=str2bool,
                        help='Require the use of TLS for all sessions')
    parser.add_argument('--tls-ca', type=str,
                        help='Filename for CA chain')
    parser.add_argument('--tls-cert', type=str,
                        help='Filename for X.509 certificate')
    parser.add_argument('--tls-key', type=str,
                        help='Filename for X.509 private key')
    parser.add_argument('--tls-dhparam', type=str,
                        help='Filename for DH parameters')
    parser.add_argument('--tls-ciphers', type=str, default=None,
                        help='Allowed TLS cipher filter')
    parser.add_argument('--stop-on-close', default=False, action='store_true',
                        help='Stop the agent when connection is closed')
    parser.add_argument('--enable-test', type=str, default=[],
                        action='append', choices=['private_extensions'],
                        help='Allowed TLS cipher filter')

    parser_listen = subp.add_parser('listen',
                                    help='Listen for TCP connections')
    parser_listen.add_argument('--address', type=str, default='',
                               help='Listen name or address')
    parser_listen.add_argument('--port', type=int, default=4556,
                               help='Listen TCP port')

    parser_conn = subp.add_parser('connect',
                                  help='Make a TCP connection')
    parser_conn.add_argument('address', type=str,
                             help='Host name or address')
    parser_conn.add_argument('--port', type=int, default=4556,
                             help='Host TCP port')

    args = parser.parse_args(argv[1:])

    logging.basicConfig(level=args.log_level.upper())
    logging.debug('command args: %s', args)

    # Must run before connection or real main loop is constructed
    DBusGMainLoop(set_as_default=True)

    config = Config()

    config.enable_test = frozenset(args.enable_test)
    config.stop_on_close = args.stop_on_close
    if args.bus_service:
        bus_serv = dbus.service.BusName(
            bus=config.bus_conn, name=args.bus_service, do_not_queue=True)
        logging.info('Registered as "%s"', bus_serv.get_name())

    if args.tls_enable:
        # attempted recommended practice of pre-master secret logging
        pmk_name = os.environ.get('SSLKEYLOGFILE')
        if pmk_name:
            try:
                import sslkeylog
                logging.info('Logging pre-master key to: %s', pmk_name)
                sslkeylog.set_keylog(pmk_name)
                print('patched', sslkeylog._patched)
            except ImportError as err:
                logging.error('Cannot use SSLKEYLOGFILE: %s', err)

        version_map = {
            None: ssl.PROTOCOL_TLS,
            '1.0': ssl.PROTOCOL_TLSv1,
            '1.1': ssl.PROTOCOL_TLSv1_1,
            '1.2': ssl.PROTOCOL_TLSv1_2,
        }
        try:
            vers_enum = version_map[args.tls_version]
        except KeyError:
            raise argparse.ArgumentTypeError('Invalid TLS version "{0}"'.format(args.tls_version))

        config.ssl_ctx = ssl.SSLContext(vers_enum)
        if args.tls_ciphers:
            config.ssl_ctx.set_ciphers(args.tls_ciphers)
        if args.tls_ca:
            config.ssl_ctx.load_verify_locations(cafile=args.tls_ca)
        if args.tls_cert or args.tls_key:
            if not args.tls_cert or not args.tls_key:
                raise RuntimeError('Neither or both of --tls-cert and --tls-key are needed')
            config.ssl_ctx.load_cert_chain(certfile=args.tls_cert, keyfile=args.tls_key)
        if args.tls_dhparam:
            config.ssl_ctx.load_dh_params(args.tls_dhparam)
        config.ssl_ctx.verify_mode = ssl.CERT_OPTIONAL

    config.nodeid = args.nodeid
    config.require_tls = args.tls_require

    if args.keepalive:
        config.keepalive_time = args.keepalive

    if args.idle:
        config.idle_time = args.idle
    else:
        config.idle_time = 2 * config.keepalive_time

    agent = Agent(config)
    if args.action == 'listen':
        agent.listen(args.address, args.port)
    elif args.action == 'connect':
        agent.connect(args.address, args.port)

    agent.exec_loop()


if __name__ == '__main__':
    sys.exit(main(*sys.argv))
