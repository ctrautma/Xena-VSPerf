# Copyright 2015 Intel Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This is a port of code provided by Xena and Flavios Xena Libraries ported
# to python 3 compatibility. Credit given to Xena and Flavio for providing
# most of the logic of this code. The code has some minor changes for PEP 8
# and python 3 conversion.
# Flavios xena libraries available at https://github.com/fleitner/XenaPythonLib

import logging
import socket
import sys
import threading
import time

# Xena Socket Commands
CMD_CLEAR_RX_STATS = 'pr_clear'
CMD_CLEAR_TX_STATS = 'pt_clear'
CMD_COMMENT = ';'
CMD_CREATE_STREAM = 'ps_create'
CMD_DELETE_STREAM = 'ps_delete'
CMD_GET_PORT_SPEED = 'p_speed ?'
CMD_GET_PORT_SPEED_REDUCTION = 'p_speedreduction ?'
CMD_GET_RX_STATS_PER_TID = 'pr_tpldtraffic'
CMD_GET_STREAM_DATA = 'pt_stream'
CMD_GET_STREAMS_PER_PORT = 'ps_indices'
CMD_GET_TID_PER_STREAM = 'ps_tpldid'
CMD_GET_TX_STATS_PER_STREAM = 'pt_stream'
CMD_GET_RX_STATS = 'pr_all ?'
CMD_GET_TX_STATS = 'pt_all ?'
CMD_INTERFRAME_GAP = 'p_interframegap'
CMD_LOGIN = 'c_logon'
CMD_LOGOFF = 'c_logoff'
CMD_OWNER = 'c_owner'
CMD_PORT = ';Port:'
CMD_RESERVE = 'p_reservation reserve'
CMD_RELEASE = 'p_reservation release'
CMD_RELINQUISH = 'p_reservation relinquish'
CMD_RESET = 'p_reset'
CMD_SET_PORT_TIME_LIMIT = 'p_txtimelimit'
CMD_SET_STREAM_HEADER_PROTOCOL = 'ps_headerprotocol'
CMD_SET_STREAM_ON_OFF = 'ps_enable'
CMD_SET_STREAM_PACKET_HEADER = 'ps_packetheader'
CMD_SET_STREAM_PACKET_LENGTH = 'ps_packetlength'
CMD_SET_STREAM_PACKET_LIMIT = 'ps_packetlimit'
CMD_SET_STREAM_PACKET_PAYLOAD = 'ps_payload'
CMD_SET_STREAM_RATE_FRACTION = 'ps_ratefraction'
CMD_SET_STREAM_TEST_PAYLOAD_ID = 'ps_tpldid'
CMD_START_TRAFFIC = 'p_traffic on'
CMD_STOP_TRAFFIC = 'p_traffic off'

_logger = logging.getLogger(__name__)
if len(_logger.handlers) == 0:
    # no parent logger available, create a temporary one
    log = logging.getLogger('local_log')
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
            '%(asctime)-15s %(levelname)-10s %(funcName)-20s ' +
            '%(lineno)-5d %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    log.setLevel(logging.DEBUG)
    _logger = log


class SimpleSocket(object):
    def __init__(self, hostname, port=5025, timeout=1):
        """Constructor
        :param hostname: hostname or ip as string
        :param port: port number to use for socket as int
        :param timeout: socket timeout as int
        :return: SimpleSocket object
        """
        self.hostname = hostname
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.sock.settimeout(timeout)
            self.sock.connect((hostname, port))
        except socket.error as msg:
            _logger.error(
                    "Cannot connect to Xena Socket at {}. Exception: {}".format(
                            hostname, msg))
            sys.exit(1)

    def __del__(self):
        """Deconstructor
        :return:
        """
        self.sock.close()

    def ask(self, cmd):
        """ Send the command over the socket
        :param cmd: cmd as string
        :return: byte utf encoded return value from socket
        """
        cmd += '\n'
        self.sock.send(cmd.encode('utf-8'))
        return self.sock.recv(1024)

    def read_reply(self):
        """ Get the response from the socket
        :return: Return the reply
        """
        reply = self.sock.recv(1024)
        if reply.find("---^".encode('utf-8')) != -1:
            # read again the syntax error msg
            reply = self.sock.recv(1024)
        return reply

    def send_command(self, cmd):
        """ Send the command specified over the socket
        :param cmd: Command to send as string
        :return: None
        """
        cmd += '\n'
        self.sock.send(cmd.encode('utf-8'))

    def set_keep_alive(self):
        """ Set the keep alive for the socket
        :return: None
        """
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)


class KeepAliveThread(threading.Thread):
    message = ''

    def __init__(self, connection, interval=10):
        """ Constructor
        :param connection: Socket for keep alive
        :param interval: interval in seconds to send keep alive
        :return: KeepAliveThread object
        """
        threading.Thread.__init__(self)
        self.connection = connection
        self.interval = interval
        self.finished = threading.Event()
        self.setDaemon(True)
        _logger.debug(
                'Xena Socket keep alive thread initiated, interval ' +
                '{} seconds'.format(self.interval))

    def stop(self):
        """ Thread stop. See python thread docs for more info
        :return: None
        """
        self.finished.set()
        self.join()

    def run(self):
        """ Thread start. See python thread docs for more info
        :return: None
        """
        while not self.finished.isSet():
            self.finished.wait(self.interval)
            self.connection.ask(self.message)


class XenaSocketDriver(SimpleSocket):
    reply_ok = '<OK>'

    def __init__(self, hostname, port=22611):
        """ Constructor
        :param hostname: Hostname or ip as string
        :param port: port to use as int
        :return: XenaSocketDriver object
        """
        SimpleSocket.__init__(self, hostname=hostname, port=port)
        SimpleSocket.set_keep_alive(self)
        self.access_semaphor = threading.Semaphore(1)

    def ask(self, cmd):
        """ Send the command over the socket in a thread safe manner
        :param cmd: Command to send
        :return: reply from socket
        """
        self.access_semaphor.acquire()
        reply = SimpleSocket.ask(self, cmd)
        self.access_semaphor.release()
        return reply

    def ask_verify(self, cmd):
        """ Send the command over the socket in a thread safe manner and
        verify the response is good.
        :param cmd: Command to send
        :return: Boolean True if command response is good, False otherwise
        """
        resp = self.ask(cmd).decode('utf-8').strip('\n')
        _logger.info('[ask_verify] {}'.format(resp))
        if resp == self.reply_ok:
            return True
        return False

    def send_command(self, cmd):
        """ Send the command over the socket with no return
        :param cmd: Command to send
        :return: None
        """
        self.access_semaphor.acquire()
        SimpleSocket.send_command(self, cmd)
        self.access_semaphor.release()

    def send_query_replies(self, cmd):
        """ Send the command over the socket and wait for all replies and return
        the lines as a list
        :param cmd: Command to send
        :return: Response from command as list
        """
        # send the command followed by cmd SYNC to find out
        # when the last reply arrives.
        self.send_command(cmd.strip('\n'))
        self.send_command('SYNC')
        replies = []
        self.access_semaphor.acquire()
        msg = SimpleSocket.read_reply(self).decode('utf-8')
        msgleft = ''
        while True:
            if '\n' in msg:
                (reply, msgleft) = msg.split('\n', 1)
                # check for syntax problems
                if reply.rfind('Syntax') != -1:
                    self.access_semaphor.release()
                    return []

                if reply.rfind('<SYNC>') == 0:

                    self.access_semaphor.release()
                    return replies

                replies.append(reply + '\n')
                msg = msgleft
            else:
                # more bytes to come
                msgnew = SimpleSocket.read_reply(self).decode('utf-8')
                msg = msgleft + msgnew


class XenaManager(object):
    def __init__(self, socketDriver, user='', password='xena'):
        """Constructor

        Establish a connection to Xena using a ``driver`` with the ``password``
        supplied.

        Attributes:
        :param socketDriver: XenaSocketDriver connection object
        :param password: Password to the Xena traffic generator
        :returns: XenaManager object
        """
        self.driver = socketDriver
        self.ports = list()

        if self.logon(password):
            _logger.info('Connected to Xena at {}'.format(self.driver.hostname))
        else:
            _logger.error('Failed to logon to Xena at {}'.format(
                    self.driver.hostname))
            return

        self.set_owner(user)

        self.keep_alive_thread = KeepAliveThread(self.driver)
        self.keep_alive_thread.start()

    def __del__(self):
        """ De-constructor
        """
        for module_port in self.ports:
            module_port.release_port()
        self.ports = []
        # self.keep_alive_thread.stop()
        self.driver.ask_verify(CMD_LOGOFF)
        # del self.keep_alive_thread

    def add_module_port(self, module, port):
        """Factory for Xena Ports

        :param module: String or int of module
        :param port: String or int of port
        :return: XenaPort object if success, None if port already added
        """
        xenaport = XenaPort(self, module, port)
        if xenaport in self.ports:
            return None
        else:
            self.ports.append(xenaport)
            return xenaport

    def get_module_port(self, module, port):
        """Return the Xena Port object if available
        :param module: module number as int or str
        :param port: port number as int or str
        :return: XenaPort object or None if not found
        """
        for p in self.ports:
            if p.port == str(port) and p.module == str(module):
                return p
        else:
            return None

    def logon(self, password):
        """Login to the Xena traffic generator using the ``password`` supplied.

        :param password: string of password
        :return: Boolean True is response OK, False if error.
        """
        return self.driver.ask_verify(make_manager_command(CMD_LOGIN, password))

    def set_owner(self, username):
        """Set the ports owner.
        :return: Boolean True is response OK, False if error.
        """
        return self.driver.ask_verify(make_manager_command(CMD_OWNER, username))


class XenaPort(object):
    def __init__(self, manager, module, port):
        """Constructor

        :param manager: XenaManager object
        :param module: Module as string or int of module to use
        :param port: Port as string or int of port to use
        :return: XenaPort object
        """
        self._manager = manager
        self._module = str(module)
        self._port = str(port)
        self._streams = list()

    @property
    def manager(self):
        """Property for manager attribute
        :return: manager object
        """
        return self._manager

    @property
    def module(self):
        """Property for module attribute
        :return: module value as string
        """
        return self._module

    @property
    def port(self):
        """Property for port attribute
        :return: port value as string
        """
        return self._port

    def port_string(self):
        """String builder with attributes
        :return: String of module port for command sequence
        """
        stringify = "{}/{}".format(self._module, self._port)
        return stringify

    def add_stream(self):
        """Add a stream to the port.
        :return: XenaStream object, None if failure
        """
        id = len(self._streams)
        stream = XenaStream(self, id)
        if self._manager.driver.ask_verify(make_stream_command(
                CMD_CREATE_STREAM, '', stream)):
            self._streams.append(stream)
            return stream
        else:
            _logger.error("Error during stream creation")
            return None

    def clear_stats(self, rx=True, tx=True):
        """Clear the port stats

        :param rx: Boolean if rx stats are to be cleared
        :param tx: Boolean if tx stats are to be cleared
        :return: Boolean True is response OK, False if error.
        """
        command = make_port_command(CMD_CLEAR_RX_STATS, self)
        res1 = self._manager.driver.ask_verify(command) if rx else True
        command = make_port_command(CMD_CLEAR_TX_STATS, self)
        res2 = self._manager.driver.ask_verify(command) if tx else True
        if all([res1, res2]):
            return True
        else:
            return False

    def get_effective_speed(self):
        port_speed = self.get_port_speed()
        reduction = self.get_port_speed_reduction()
        effective_speed = port_speed * (1.0 - reduction / 1000000.0)
        return effective_speed

    def get_inter_frame_gap(self):
        """
        Get the interframe gap and return it as string
        :return: integer of interframe gap
        """
        command = make_port_command(CMD_INTERFRAME_GAP + '?', self)
        res = self._manager.driver.ask(command).decode('utf-8')
        res = int(res.rstrip('\n').split(' ')[-1])
        return res

    def get_port_speed(self):
        """
        Get the port speed as bits from port and return it as a int.
        :return: Int of port speed
        """
        command = make_port_command(CMD_GET_PORT_SPEED, self)
        res = self._manager.driver.ask(command).decode('utf-8')
        port_speed = res.split(' ')[-1].rstrip('\n')
        return int(port_speed) * 1000000

    def get_port_speed_reduction(self):
        """
        Get the port speed reduction value as int
        :return: Integer of port speed reduction value
        """
        command = make_port_command(CMD_GET_PORT_SPEED_REDUCTION, self)
        res = self._manager.driver.ask(command).decode('utf-8')
        res = int(res.rstrip('\n').split(' ')[-1])
        return res

    def get_rx_stats(self):
        """Get the rx stats and return the data as a dict.
        :return: Receive stats as dictionary
        """
        command = make_port_command(CMD_GET_RX_STATS, self)
        rxData = self._manager.driver.send_query_replies(command)
        data = XenaRXStats(rxData, time.time())
        return data

    def get_tx_stats(self):
        """Get the tx stats and return the data as a dict.
        :return: Receive stats as dictionary
        """
        command = make_port_command(CMD_GET_TX_STATS, self)
        txData = self._manager.driver.send_query_replies(command)
        data = XenaTXStats(txData, time.time())
        return data

    def release_port(self):
        """Release the port
        :return: Boolean True is response OK, False if error.
        """
        command = make_port_command(CMD_RELEASE, self)
        return self._manager.driver.ask_verify(command)

    def reserve_port(self):
        """Reserve the port
        :return: Boolean True is response OK, False if error.
        """
        command = make_port_command(CMD_RESERVE, self)
        return self._manager.driver.ask_verify(command)

    def reset_port(self):
        """Reset the port
        :return: Boolean True is response OK, False if error.
        """
        command = make_port_command(CMD_RESET, self)
        return self._manager.driver.ask_verify(command)

    def set_port_time_limit(self, ms):
        """Set the port time limit in ms
        :param ms: ms for port time limit
        :return: Boolean True is response OK, False if error.
        """
        command = make_port_command('{} {}'.format(
                CMD_SET_PORT_TIME_LIMIT, ms), self)
        return self._manager.driver.ask_verify(command)

    def traffic_off(self):
        """Start traffic
        :return: Boolean True is response OK, False if error.
        """
        command = make_port_command(CMD_STOP_TRAFFIC, self)
        return self._manager.driver.ask_verify(command)

    def traffic_on(self):
        """Stop traffic
        :return: Boolean True is response OK, False if error.
        """
        command = make_port_command(CMD_START_TRAFFIC, self)
        return self._manager.driver.ask_verify(command)


class XenaStream(object):
    def __init__(self, xenaPort, streamID):
        """Constructor

        :param xenaPort: XenaPort object
        :param streamID: Stream ID as int or string
        :return: XenaStream object
        """
        self._xenaPort = xenaPort
        self._streamID = str(streamID)
        self._manager = self._xenaPort.manager

    @property
    def xenaPort(self):
        """Property for port attribute
        :return: XenaPort object
        """
        return self._xenaPort

    @property
    def streamID(self):
        """Property for streamID attribute
        :return: streamID value as string
        """
        return self._streamID

    def get_stream_data(self):
        command = make_stream_command(CMD_GET_STREAM_DATA, '?', self)
        res = self._manager.driver.ask(command).decode('utf-8')
        return res

    def set_header_protocol(self, protocolheader):
        """Set the header info for the packet header hex.
        If the packet header contains just Ethernet and IP info then call this
        method with ETHERNET IP as the protocol header.

        :param protocolheader: protocol header argument
        :return: Boolean True if success, False if error
        """
        command = make_stream_command(
            CMD_SET_STREAM_HEADER_PROTOCOL,
            protocolheader, self)
        return self._manager.driver.ask_verify(command)

    def set_off(self):
        """Set the stream to off
        :return: Boolean True if success, False if error
        """
        return self._manager.driver.ask_verify(make_stream_command(
                CMD_SET_STREAM_ON_OFF, 'off', self))

    def set_on(self):
        """Set the stream to on
        :return: Boolean True if success, False if error
        """
        return self._manager.driver.ask_verify(make_stream_command(
                CMD_SET_STREAM_ON_OFF, 'on', self))

    def set_packet_header(self, header):
        """Set the stream packet header

        :param header: packet header as hex bytes
        :return: Boolean True if success, False if error
        """
        return self._manager.driver.ask_verify(make_stream_command(
                CMD_SET_STREAM_PACKET_HEADER, header, self))

    def set_packet_length(self, patternType, min, max):
        """Set the pattern length with min and max values based on the pattern
        type supplied

        :param patternType: String of pattern type, valid entries [ fixed,
         butterfly, random, mix, incrementing ]
        :param min: integer of minimum byte value
        :param max: integer of maximum byte value
        :return: Boolean True if success, False if error
        """
        return self._manager.driver.ask_verify(make_stream_command(
                CMD_SET_STREAM_PACKET_LENGTH, '{} {} {}'.format(
                        patternType, min, max), self))

    def set_packet_limit(self, limit):
        """Set the packet limit

        :param limit: number of packets that will be sent, use -1 to disable
        :return: Boolean True if success, False if error
        """
        return self._manager.driver.ask_verify(make_stream_command(
                CMD_SET_STREAM_PACKET_LIMIT, limit, self))

    def set_packet_payload(self, payloadType, hexValue):
        """Set the payload to the hex value based on the payload type

        :param payloadType: string of the payload type, valid entries [ pattern,
         incrementing, prbs ]
        :param hexValue: hex string of valid hex
        :return: Boolean True if success, False if error
        """
        return self._manager.driver.ask_verify(make_stream_command(
                CMD_SET_STREAM_PACKET_PAYLOAD, '{} {}'.format(
                        payloadType, hexValue), self))

    def set_rate_fraction(self, fraction):
        """Set the rate fraction

        :param fraction: fraction for the stream
        :return: Boolean True if success, False if error
        """
        return self._manager.driver.ask_verify(make_stream_command(
                CMD_SET_STREAM_RATE_FRACTION, fraction, self))

    def set_payload_id(self, id):
        """ Set the test payload ID
        :param id: ID as int or string
        :return: Boolean True if success, False if error
        """
        return self._manager.driver.ask_verify(make_stream_command(
                CMD_SET_STREAM_TEST_PAYLOAD_ID, id, self))


class XenaRXStats(object):
    def __init__(self, stats, epoc):
        """ Constructor
        :param stats: Stats from pr all command as list
        :param epoc: Current time in epoc
        :return: XenaRXStats object
        """
        self._stats = stats
        self._time = epoc
        self.data = self.parse_stats()
        self.preamble = 8

    def _pack_stats(self, param, start, fields=None):
        """ Pack up the list of stats in a dictionary
        :param param: The list of params to process
        :param start: What element to start at
        :param fields: The field names to pack as keys
        :return: Dictionary of data where fields match up to the params
        """
        if not fields:
            fields = ['bps', 'pps', 'bytes', 'packets']
        data = {}
        i = 0
        for column in fields:
            data[column] = int(param[start + i])
            i += 1

        return data

    def _pack_rxextra_stats(self, param, start):
        """ Pack up the extra stats
        :param param: List of params to pack
        :param start: What element to start at
        :return: Dictionary of stats
        """
        fields = [ 'fcserrors', 'pauseframes', 'arprequests', 'arpreplies',
                   'pingrequests', 'pingreplies', 'gapcount', 'gapduration' ]
        return self._pack_stats(param, start, fields)

    def _pack_tplds_stats(self, param, start):
        """ Pack up the tplds stats
        :param param: List of params to pack
        :param start: What element to start at
        :return: Dictionary of stats
        """
        data = {}
        i = 0
        for val in range(start, len(param) - start):
            data[i] = int(param[val])
            i += 1
        return data

    def _pack_tplderrors_stats(self, param, start):
        """ Pack up tlpd errors
        :param param: List of params to pack
        :param start: What element to start at
        :return: Dictionary of stats
        """
        fields = ['dummy', 'seq', 'mis', 'pld']
        return self._pack_stats(param, start, fields)

    def _pack_tpldlatency_stats(self, param, start):
        """ Pack up the tpld latency stats
        :param param: List of params to pack
        :param start: What element to start at
        :return: Dictionary of stats
        """
        fields = ['min', 'avg', 'max', '1sec']
        return self._pack_stats(param, start, fields)

    def _pack_tpldjitter_stats(self, param, start):
        """ Pack up the tpld jitter stats
        :param param: List of params to pack
        :param start: What element to start at
        :return: Dictionary of stats
        """
        fields = ['min', 'avg', 'max', '1sec']
        return self._pack_stats(param, start, fields)

    @property
    def time(self):
        """
        :return: Time as String of epoc of when stats were collected
        """
        return self._time

    def parse_stats(self):
        """ Parse the stats from pr all command
        :return: Dictionary of all stats
        """
        statdict = {}
        for line in self._stats:
            param = line.split()
            if param[1] == 'PR_TOTAL':
                statdict['pr_total'] = self._pack_stats(param, 2)
            elif param[1] == 'PR_NOTPLD':
                statdict['pr_notpld'] = self._pack_stats(param, 2,)
            elif param[1] == 'PR_EXTRA':
                statdict['pr_extra'] = self._pack_rxextra_stats(param, 2)
            elif param[1] == 'PT_STREAM':
                entry_id = "pt_stream_%s" % param[2].strip('[]')
                statdict[entry_id] = self._pack_stats(param, 3)
            elif param[1] == 'PR_TPLDS':
                tid_list = self._pack_tplds_stats(param, 2)
                if len(tid_list):
                    statdict['pr_tplds'] = tid_list
            elif param[1] == 'PR_TPLDTRAFFIC':
                if 'pr_tpldstraffic' in statdict:
                    data = statdict['pr_tpldstraffic']
                else:
                    data = {}
                entry_id = param[2].strip('[]')
                data[entry_id] = self._pack_stats(param, 3)
                statdict['pr_tpldstraffic'] = data
            elif param[1] == 'PR_TPLDERRORS':
                if 'pr_tplderrors' in statdict:
                    data = statdict['pr_tplderrors']
                else:
                    data = {}
                entry_id = param[2].strip('[]')
                data[entry_id] = self._pack_tplderrors_stats(param, 3)
                statdict['pr_tplderrors'] = data
            elif param[1] == 'PR_TPLDLATENCY':
                if 'pr_tpldlatency' in statdict:
                    data = statdict['pr_tpldlatency']
                else:
                    data = {}
                entry_id = param[2].strip('[]')
                data[entry_id] = self._pack_tpldlatency_stats(param, 3)
                statdict['pr_tpldlatency'] = data
            elif param[1] == 'PR_TPLDJITTER':
                if 'pr_tpldjitter' in statdict:
                    data = statdict['pr_tpldjitter']
                else:
                    data = {}
                entry_id = param[2].strip('[]')
                data[entry_id] = self._pack_tpldjitter_stats(param, 3)
                statdict['pr_pldjitter'] = data
            elif param[1] == 'PR_FILTER':
                if 'pr_filter' in statdict:
                    data = statdict['pr_filter']
                else:
                    data = {}
                entry_id = param[2].strip('[]')
                data[entry_id] = self._pack_stats(param, 3)
                statdict['pr_filter'] = data
            elif param[1] == 'P_RECEIVESYNC':
                if param[2] == 'IN_SYNC':
                    statdict['p_receivesync' ] = { 'IN SYNC' : 'True' }
                else:
                    statdict['p_receivesync' ] = { 'IN SYNC' : 'False' }
            else:
                logging.warning("XenaPort: unknown stats: %s", param[1])

        mydict = dict()
        mydict[self._time] = statdict
        return mydict


class XenaTXStats(object):
    def __init__(self, stats, epoc):
        """ Constructor
        :param stats: Stats from pt all command as list
        :param epoc: Current time in epoc
        :return: XenaTXStats object
        """
        self._stats = stats
        self._time = epoc
        self._ptstreamkeys = list()
        self.data = self.parse_stats()
        self.preamble = 8

    def _pack_stats(self, params, start, fields=None):
        """ Pack up the list of stats in a dictionary
        :param params: The list of params to process
        :param start: What element to start at
        :param fields: The field names to pack as keys
        :return: Dictionary of data where fields match up to the params
        """
        if not fields:
            fields = ['bps', 'pps', 'bytes', 'packets']
        data = {}
        i = 0
        for column in fields:
            data[column] = int(params[start + i])
            i += 1

        return data

    def _pack_txextra_stats(self, params, start):
        """ Pack up the tx extra stats
        :param params: List of params to pack
        :param start: What element to start at
        :return: Dictionary of stats
        """
        fields = ['arprequests', 'arpreplies', 'pingrequests', 'pingreplies',
                  'injectedfcs', 'injectedseq', 'injectedmis', 'injectedint',
                  'injectedtid', 'training']
        return self._pack_stats(params, start, fields)

    @property
    def pt_stream_keys(self):
        """
        :return: Return a list of pt_stream_x stream key ids
        """
        return self._ptstreamkeys

    @property
    def time(self):
        """
        :return: Time as String of epoc of when stats were collected
        """
        return self._time

    def parse_stats(self):
        """ Parse the stats from pr all command
        :return: Dictionary of all stats
        """
        statdict = {}
        for line in self._stats:
            param = line.split()
            if param[1] == 'PT_TOTAL':
                statdict['pt_total'] = self._pack_stats(param, 2)
            elif param[1] == 'PT_NOTPLD':
                statdict['pt_notpld'] = self._pack_stats(param, 2,)
            elif param[1] == 'PT_EXTRA':
                statdict['pt_extra'] = self._pack_txextra_stats(param, 2)
            elif param[1] == 'PT_STREAM':
                entry_id = "pt_stream_%s" % param[2].strip('[]')
                self._ptstreamkeys.append(entry_id)
                statdict[entry_id] = self._pack_stats(param, 3)
            else:
                logging.warning("XenaPort: unknown stats: %s", param[1])
        mydict = dict()
        mydict[self._time] = statdict
        return mydict


def packets_per_second(packets, duration):
    """
    Return the pps as float
    :param packets: total packets
    :param duration: time in seconds
    :return: float of pps
    """
    return packets / duration


def l2_bit_rate(packet_size, preamble, pps):
    """
    Return the l2 bit rate
    :param packet_size: packet size on the line in bytes
    :param preamble: preamble size of the packet header in bytes
    :param pps: packets per second
    :return: l2 bit rate as float
    """
    return (packet_size * preamble) * pps


def l1_bit_rate(l2br, pps, ifg, preamble):
    """
    Return the l1 bit rate
    :param l2br: l2 bit rate int bits per second
    :param pps: packets per second
    :param ifg: the inter frame gap
    :param preamble: preamble size of the packet header in bytes
    :return: l1 bit rate as float
    """
    return l2br + (pps * ifg * preamble)


def make_manager_command(cmd, argument):
    """ String builder for Xena socket commands

    :param cmd: Command to send
    :param argument: Arguments for command to send
    :return: String of command
    """
    command = '{} "{}"'.format(cmd, argument)
    _logger.info("[Command Sent] : {}".format(command))
    return command


def make_port_command(cmd, xenaPort):
    """ String builder for Xena port commands

    :param cmd: Command to send
    :param xenaPort: XenaPort object
    :return: String of command
    """
    command = "{} {}".format(xenaPort.port_string(), cmd)
    _logger.info("[Command Sent] : {}".format(command))
    return command


def make_stream_command(cmd, args, xenaStream):
    """ String builder for Xena port commands

    :param cmd: Command to send
    :param xenaStream: XenaStream object
    :return: String of command
    """
    command = "{} {} [{}] {}".format(xenaStream.xenaPort.port_string(), cmd,
                                     xenaStream.streamID, args)
    _logger.info("[Command Sent] : {}".format(command))
    return command


if __name__ == '__main__':
    packetsize = 64
    duration = 10
    driver = XenaSocketDriver('10.19.15.19')
    xm = XenaManager(driver, 'vsperf', 'xena')
    port0 = xm.add_module_port(3, 0)
    port1 = xm.add_module_port(3, 1)
    port0.reserve_port()
    port1.reserve_port()
    port0.reset_port()
    port1.reset_port()
    p0s0 = port0.add_stream()
    p0s0.set_on()
    p0s0.set_packet_header('0x525400c61020525400c61010080045000014000100004' +
                           '00066e70a0000010a000002')
    p0s0.set_packet_length('fixed', packetsize, 16383)
    p0s0.set_packet_payload('incrementing', '0x00')
    p0s0.set_packet_limit(-1)
    p0s0.set_rate_fraction(1000000)
    p0s0.set_payload_id(0)
    port0.set_port_time_limit(1000000 * duration)
    port0.clear_stats()
    port1.clear_stats()
    port0.traffic_on()
    time.sleep(11)
    port0.traffic_off()
    txstat = port0.get_tx_stats()
    rxstat = port1.get_rx_stats()
    print(txstat.data)
    print(rxstat.data)
    gap = port0.get_inter_frame_gap()
    rxpps = packets_per_second(rxstat.data[rxstat.time]['pr_total']['packets'],
                               duration)
    l2rxbr = l2_bit_rate(packetsize, rxstat.preamble, rxpps)
    l1rxbr = l1_bit_rate(l2rxbr, rxpps, gap, rxstat.preamble)
    print("RXl1BR: {}".format(l1rxbr))
    txpps = packets_per_second(txstat.data[txstat.time]['pt_total']['packets'],
                               duration)
    l2txbr = l2_bit_rate(packetsize, txstat.preamble, txpps)
    l1txbr = l1_bit_rate(l2txbr, txpps, gap, txstat.preamble)
    print("TXl1BR: {}".format(l1txbr))
    print("RXPercentage = {}".format(
        100.0 * l1rxbr / port0.get_effective_speed()))
    print("TXPercentage = {}".format(
        100.0 * l1txbr / port1.get_effective_speed()))

