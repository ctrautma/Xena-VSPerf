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
"""
Xena Traffic Generator Model
"""

# TODO update Back2Back method description when Result implementation will
# be ready.

# TODO CT List of things that need to be completed
# 1. Fix results to trafficgen guide standard of result_constants.py in
# core/results/result_constants.py
# 2. Numpkts in params should be moved to config file
# 3. Move port, ip, logon name to config file per traffic gen spec
# 4. Integrate traffic param spec from traffic defaults with merge

# VSPerf imports
from trafficgenhelper import TRAFFIC_DEFAULTS, merge_spec
# import trafficgen

# python imports
import binascii
import json
import logging
import os
import subprocess
import sys
import time as Time
import xml.etree.ElementTree as ET

# XenaDriver
import XenaDriver

# scapy imports
# pip install scapy to install on python 2.x
# pip install scapy-python3 for python 3.x
import scapy.layers.inet as inet

# TODO need to move this to the conf file as other generators use -CT
TRAFFICGEN_IP = '10.19.15.19'
TRAFFICGEN_PORT1 = '0'
TRAFFICGEN_PORT2 = '1'
TRAFFICGEN_USER = 'vsperf'
TRAFFICGEN_MODULE1 = '3'
TRAFFICGEN_MODULE2 = '3'

# This needs to be changed to inherit the trafficgen.ITrafficGenerator abstract
# class. I have left it out currently because it calls into specific VSPerf
# modules that I did not want to include in this implementation. -CT


class Xena(object):
    """
    Xena Traffic generator wrapper
    """
    _traffic_defaults = TRAFFIC_DEFAULTS.copy()
    _logger = logging.getLogger(__name__)

    def __init__(self):
        self.mono_pipe = None
        self.xm = None

    @property
    def traffic_defaults(self):
        """Default traffic values.

        These can be expected to be constant across traffic generators,
        so no setter is provided. Changes to the structure or contents
        will likely break traffic generator implementations or tests
        respectively.
        """
        return self._traffic_defaults

    def __enter__(self):
        """Connect to the traffic generator.

        Provide a context manager interface to the traffic generators.
        This simply calls the :func:`connect` function.
        """
        return self.connect()

    def __exit__(self, type_, value, traceback):
        """Disconnect from the traffic generator.

        Provide a context manager interface to the traffic generators.
        This simply calls the :func:`disconnect` function.
        """
        self.disconnect()

    def _build_test_packet(self):
        """
        Build a packet header based on traffic profile using scapy external
        libraries.
        """
        l2 = inet.Ether(src=TRAFFIC_DEFAULTS['l2']['srcmac'],
                        dst=TRAFFIC_DEFAULTS['l2']['dstmac'])
        l3 = inet.IP(src=TRAFFIC_DEFAULTS['l3']['srcip'],
                     dst=TRAFFIC_DEFAULTS['l3']['dstip'],
                     proto=TRAFFIC_DEFAULTS['l3']['proto'])
        # L4 = inet.TCP(src=TRAFFIC_DEFAULTS['l2']['srcport'],
        #              dst=TRAFFIC_DEFAULTS['l2']['dstport'])
        packet = l2/l3
        packet_bytes = bytes(packet)
        packet_hex = '0x' + binascii.hexlify(packet_bytes)
        return packet_hex
        # TODO VLANS needs to addressed as well.

    def connect(self):
        """Connect to the traffic generator.

        This is an optional function, designed for traffic generators
        which must be "connected to" (i.e. via SSH or an API) before
        they can be used. If not required, simply do nothing here.

        Where implemented, this function should raise an exception on
        failure.

        :returns: None
        """
        self._xsocket = XenaDriver.XenaSocketDriver(TRAFFICGEN_IP)
        # create the manager session
        self.xm = XenaDriver.XenaManager(self._xsocket, 'xena')

    def disconnect(self):
        """Disconnect from the traffic generator.

        As with :func:`connect`, this function is optional.

        Where implemented, this function should raise an exception on
        failure.

        :returns: None
        """
        self._xsocket.disconnect()

    def send_burst_traffic(self, traffic=None, numpkts=100,
                           time=20, framerate=100):
        """Send a burst of traffic.

        Send a ``numpkts`` packets of traffic, using ``traffic``
        configuration, with a timeout of ``time``.

        Attributes:
        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN tags
        :param numpkts: Number of packets to send
        :param framerate: Expected framerate
        :param time: Time to wait to receive packets

        :returns: dictionary of strings with following data:
            - List of Tx Frames,
            - List of Rx Frames,
            - List of Tx Bytes,
            - List of List of Rx Bytes,
            - Payload Errors and Sequence Errors.
        """

        self._params = {}
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        if not self.xm:
            self.connect()

        port0 = self.xm.add_module_port(TRAFFICGEN_MODULE1, TRAFFICGEN_PORT1)
        if not port0:
            self._logger.debug("Fail to add port " + str(TRAFFICGEN_PORT1))
            sys.exit(-1)

        port1 = self.xm.add_module_port(TRAFFICGEN_MODULE2, TRAFFICGEN_PORT2)
        if not port1:
            self._logger.debug("Fail to add port" + str(TRAFFICGEN_PORT2))
            sys.exit(-1)

        # Clear port configuration for a clean start
        port0.reset_port()
        port1.reset_port()

        port0.reserve_port()
        port1.reserve_port()

        # Add one stream for port 0
        s1_p0 = port0.add_stream()
        s1_p0.set_on()

        # setup stream params
        s1_p0.set_packet_header(self._build_test_packet())
        s1_p0.set_packet_length('fixed',
                TRAFFIC_DEFAULTS['l2']['framesize'], 16383)
        s1_p0.set_packet_payload('incrementing', '0x00')
        s1_p0.set_packet_limit(numpkts)
        s1_p0.set_rate_fraction(framerate*10000),
        s1_p0.set_payload_id(0)

        port0.clear_stats()
        port1.clear_stats()

        # start/[wait]/stop the traffic
        if not port0.traffic_on():
            self._logger.debug(
                    "Failure to start traffic. Check settings and retry.")
            sys.exit(1)
        Time.sleep(time)
        port0.traffic_off()

        # getting results
        tx_stats = port0.get_tx_stats().data
        rx_stats = port1.get_rx_stats().data

        txkey = tx_stats.keys()[0]
        rxkey = rx_stats.keys()[0]

        # TODO implement multiple stream stats.
        result = dict()
        result['framesSent'] = tx_stats[txkey]['pt_stream_0']['packets']
        result['framesRecv'] = rx_stats[
            rxkey]['pr_tpldstraffic']['0']['packets']
        result['bytesSent'] = tx_stats[txkey]['pt_stream_0']['bytes']
        result['bytesRecv'] = rx_stats[rxkey]['pr_tpldstraffic']['0']['bytes']
        result['payError'] = rx_stats[rxkey]['pr_tplderrors']['0']['pld']
        result['seqError'] = rx_stats[rxkey]['pr_tplderrors']['0']['seq']

        return result

    def send_cont_traffic(self, traffic=None, numpkts=100, time=20,
                          framerate=0):
        """Send a continuous flow of traffic.r

        Send packets at ``framerate``, using ``traffic`` configuration,
        until timeout ``time`` occurs.

        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN tags
        :param time: Time to wait to receive packets (secs)
        :param framerate: Expected framerate
        :param multistream: Enable multistream output by overriding the
                        UDP port number in ``traffic`` with values
                        from 1 to 64,000
        :returns: dictionary of strings with following data:
            - Tx Throughput (fps),
            - Rx Throughput (fps),
            - Tx Throughput (mbps),
            - Rx Throughput (mbps),
            - Tx Throughput (% linerate),
            - Rx Throughput (% linerate),
            - Min Latency (ns),
            - Max Latency (ns),
            - Avg Latency (ns)
        """

        self._params = {}
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        if self.xm == None:
            self.connect()

        port0 = self.xm.add_module_port(TRAFFICGEN_MODULE1, TRAFFICGEN_PORT1)
        if not port0:
            self._logger.debug("Fail to add port " + str(TRAFFICGEN_PORT1))
            sys.exit(-1)

        port1 = self.xm.add_module_port(TRAFFICGEN_MODULE2, TRAFFICGEN_PORT2)
        if not port1:
            self._logger.debug("Fail to add port" + str(TRAFFICGEN_PORT2))
            sys.exit(-1)

        s1_p0 = port0.add_stream()
        s1_p0.set_on()
        s1_p0.set_packet_limit(-1)  # for continuous flow

        s1_p0.set_rate_fraction(1000000)
        s1_p0.set_packet_header(self._build_test_packet())
        s1_p0.set_packet_length('fixed', TRAFFIC_DEFAULTS['l2']['framesize'],
                                      16383)
        s1_p0.set_packet_payload('incrementing', '0x00')

        # CT Is this really needed since we set the automatic stop below?
        # s1_p0.set_packet_limit(numpkts)
        s1_p0.set_payload_id(0)

        port0.set_port_time_limit(time*1000)  # automatic stop

        # TODO CT is this ok to clear these again?
        port0.clear_stats()
        port1.clear_stats()

        # start the traffic
        port0.traffic_on()
        Time.sleep(time)

        # getting results
        tx_stats = port0.get_tx_stats().data
        rx_stats = port1.get_rx_stats().data

        print(tx_stats)
        print(rx_stats)

        txkey = tx_stats.keys()[0]
        rxkey = rx_stats.keys()[0]

        # TODO need to implement multistream stat collection CT
        result = {}
        result['Tx Throughput fps'] = tx_stats[txkey]['pt_stream_0']['pps']
        result['Rx Throughput fps'] = rx_stats[rxkey]['pr_tpldstraffic']['0']['pps']
        result['Tx Throughput mbps'] = tx_stats[txkey]['pt_stream_0']['bps'] * 1000
        result['Rx Throughput mbps'] = rx_stats[rxkey]['pr_tpldstraffic']['0']['bps'] * 1000

        # TODO: Find port speed and % linerate out of it (based on framesize)
        # result['Tx Throughput % linerate'] = tx_stats[pt_stream_0][0]
        # result['Rx Throughput % linerate'] = rx_stats[pr_tpldstraffic][0][0]

        # ## TODO: Find naming convention for the following:
        result['latency min'] = rx_stats[rxkey]['pr_tpldlatency']['0']['min']
        result['latency max'] = rx_stats[rxkey]['pr_tpldlatency']['0']['max']
        result['latency avg'] = rx_stats[rxkey]['pr_tpldlatency']['0']['avg']

        print(result)
        return result

    def start_cont_traffic(self, traffic=None, time=20, framerate=0):
        """Non-blocking version of 'send_cont_traffic'.

        Start transmission and immediately return. Do not wait for
        results.
        """

        self._params = {}
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        if not self.xm:
            self.connect()

        port0 = self.xm.add_port(TRAFFICGEN_MODULE1, TRAFFICGEN_PORT1)
        if not port0:
            self._logger.debug("Fail to add port " + str(TRAFFICGEN_PORT1))
            sys.exit(-1)

        port1 = self.xm.add_port(TRAFFICGEN_MODULE2, TRAFFICGEN_PORT2)
        if not port1:
            self._logger.debug("Fail to add port" + str(TRAFFICGEN_PORT2))
            sys.exit(-1)

        s1_p0 = port0.add_stream(1)
        s1_p0.set_on()
        s1_p0.set_packet_limit(-1)  # for continues flow

        s1_p0.set_rate_fraction()
        s1_p0.set_packet_header(self._build_test_packet())
        s1_p0.set_packet_length('fixed', TRAFFIC_DEFAULTS['l2']['framesize'],
                                16383)
        s1_p0.set_packet_payload('incrementing', '0x00')

        # This is a non blocking traffic start. Why are we setting a limit? CT
        # s1_p0.set_tx_time_limit_ms(time*1000)

        s1_p0.set_payload_id(0)

        # start the traffic and return
        port0.traffic_on()

    def stop_cont_traffic(self):
        """Stop continuous transmission and return results.
        """
        port0 = self.xm.get_module_port(TRAFFICGEN_MODULE1, TRAFFICGEN_PORT1)
        port0.traffic_off()

        # TODO, need a return here of the results per spec -CT
        # TODO Although I'm not sure what results they want??

    def send_rfc2544_throughput(self, traffic=None, trials=1, duration=20,
                                lossrate=0.0):

        self._params = {}
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        # Read configuration file to variable
        with open('./Configuration.x2544','r',encoding='utf-8') as data_file:
            x2544_Configuration = json.loads(data_file.read())

        x2544_Configuration['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Iterations'] = trials
        x2544_Configuration['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Duration'] = duration
        x2544_Configuration['TestOptions']['TestTypeOptionMap']['Throughput'][
            'RateIterationOptions']['AcceptableLoss'] = lossrate

        """
        :param multistream: Enable multistream output by overriding the UDP port
        number in ``traffic`` with values from 1 to 64,000
        """

        # if multistream=='enabled':
        #    for guid in x2544_Configuration[
        #        'StreamProfileHandler']['ProfileAssignmentMap']:
        #        guid = '929c6cd5-c4fd-40a1-a27f-6ef4ed755289'
        # else:
        #    e9fa2efa-57e0-41f1-9a0c-b01d0e91925e

        # Write modified to the file that is expetedTo(2) Be(b) Used.
        with open("./2bUsed.x2544", 'w',encoding='utf-8') as f:
            json.dump(x2544_Configuration, f, indent = 2,sort_keys = True,
                      ensure_ascii=True)

        args=["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e"]
        subprocess.call(args)

        # result_dict = OrderedDict()
        result_dict = {}
        root = ET.parse(r'{}/{}/xena2544-report.xml'.format(
                os.path.expanduser('~'), 'Xena/Xena2544-2G/Reports')).getroot()

        result_dict['THROUGHPUT_TX_FPS'] = root[0][1][0].get('TotalTxRateFps')
        result_dict['THROUGHPUT_TX_MBPS'] = int(root[0][1][0].get(
                'TotalTxRateBpsL2'))/1000
        result_dict['THROUGHPUT_TX_PERCENT'] = root[0][1][0].get(
                'TotalTxRatePcnt')
        result_dict['THROUGHPUT_RX_PERCENT'] = (100 - int(root[0][1][0].get(
                'TotalLossRatioPcnt'))) * int(root[0][1][0].get(
                    'TotalTxRatePcnt'))
        # This is done for port 0. We can change last 0 to 1 to get port 1
        # results,
        result_dict['MIN_LATENCY_NS'] = root[0][1][0][0].get('MinLatency')
        result_dict['MAX_LATENCY_NS'] = root[0][1][0][0].get('MaxLatency')
        result_dict['AVG_LATENCY_NS'] = root[0][1][0][0].get('AvgLatency')
        return result_dict

    def start_rfc2544_throughput(self, traffic=None, trials=3, duration=20,
                                 lossrate=0.0):
        """Non-blocking version of 'send_rfc2544_throughput'.

        Start transmission and immediately return. Do not wait for
        results.
        """

        self._params = {}
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        # Read configuration file to variable
        with open('./Configuration.x2544','r',encoding='utf-8') as data_file:
            x2544_Configuration = json.loads(data_file.read())

        x2544_Configuration['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Iterations'] = trials
        x2544_Configuration['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Duration'] = duration
        x2544_Configuration['TestOptions']['TestTypeOptionMap']['Throughput'][
            'RateIterationOptions']['AcceptableLoss'] = lossrate

        """
        :param multistream: Enable multistream output by overriding the UDP port
        number in ``traffic`` with values from 1 to 64,000
        """

        #if multistream=='enabled':
        #    for guid in x2544_Configuration['StreamProfileHandler']['ProfileAssignmentMap']:
        #        guid = '929c6cd5-c4fd-40a1-a27f-6ef4ed755289'
        #else:
        #    e9fa2efa-57e0-41f1-9a0c-b01d0e91925e


        # Write modified to the file that is expetedTo(2) Be(b) Used.
        with open("./2bUsed.x2544", 'w',encoding='utf-8') as f:
            json.dump(x2544_Configuration, f, indent = 2,sort_keys = True,
                      ensure_ascii=True)

        args=["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e"]
        self.mono_pipe = subprocess.popen(args)

    def wait_rfc2544_throughput(self):
        """Wait for and return results of RFC2544 test.
        """
        is_running = self.mono_pipe.communicate()[0]
        result_dict = {}
        root = ET.parse(r'./xena2544-report.xml').getroot()

        result_dict['THROUGHPUT_TX_FPS'] = root[0][1][0].get('TotalTxRateFps')
        result_dict['THROUGHPUT_TX_MBPS'] = int(root[0][1][0].get(
                'TotalTxRateBpsL2'))/1000
        result_dict['THROUGHPUT_TX_PERCENT'] = root[0][1][0].get(
                'TotalTxRatePcnt')
        result_dict['THROUGHPUT_RX_PERCENT']  =  (100 - int(root[0][1][0].get(
                'TotalLossRatioPcnt'))) * int(root[0][1][0].get(
                    'TotalTxRatePcnt'))
        # This is done for port 0. We can change last 0 to 1 to get port 1
        # results,
        result_dict['MIN_LATENCY_NS'] = root[0][1][0][0].get('MinLatency')
        result_dict['MAX_LATENCY_NS'] = root[0][1][0][0].get('MaxLatency')
        result_dict['AVG_LATENCY_NS'] =  root[0][1][0][0].get('AvgLatency')
        return result_dict

    def send_rfc2544_back2back(self, traffic=None, trials=1, duration=20,
                               lossrate=0.0):
        """Send traffic per RFC2544 back2back test specifications.

        Send packets at a fixed rate, using ``traffic``
        configuration, until minimum time at which no packet loss is
        detected is found.

        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN
            tags
        :param trials: Number of trials to execute
        :param duration: Per iteration duration
        :param lossrate: Acceptable loss percentage
        :param multistream: Enable multistream output by overriding the
            UDP port number in ``traffic`` with values from 1 to 64,000

        :returns: Named tuple of Rx Throughput (fps), Rx Throughput (mbps),
            Tx Rate (% linerate), Rx Rate (% linerate), Tx Count (frames),
            Back to Back Count (frames), Frame Loss (frames), Frame Loss (%)
        :rtype: :class:`Back2BackResult`
        """

        self._params = {}
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        raise NotImplementedError('Please call an implementation.')

    def start_rfc2544_back2back(self, traffic=None, trials=1, duration=20,
                                lossrate=0.0):
        """Non-blocking version of 'send_rfc2544_back2back'.

        Start transmission and immediately return. Do not wait for
        results.
        """

        self._params = {}
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        raise NotImplementedError('Please call an implementation.')

    def wait_rfc2544_back2back(self):
        """Wait and set results of RFC2544 test.
        """
        raise NotImplementedError('Please call an implementation.')


if __name__ == "__main__":
    # XenaPythonLib logging
    debugOn = False
    for debugs in sys.argv:
        if debugs in ['debug', '-d', 'Debug', '-D']:
            debugOn = True
    logging.basicConfig(level=logging.DEBUG) if debugOn else \
        logging.basicConfig(level=logging.INFO)

    result = dict()
    xena_obj = Xena()
    print("What method to test?")
    print("1. send_rfc2544_throughput")
    print("2. send_burst_traffic")
    print("3. send_cont_traffic/stop_cont_traffic")
    print("4. Quit")
    ans = 0
    while ans not in ('1', '2', '3', '4'):
        if sys.version[0] == '3':
            print("Version 3")
            ans = input("> ")
        else:
            print("Version 2")
            ans = raw_input("> ")
        try:
            if int(ans) > 0 and int(ans) < 5:
                break
            else:
                print("!!Invalid entry!!")
        except TypeError:
            print("!!Invalid entry!!")
    if ans == '1':
        result = xena_obj.send_rfc2544_throughput()
    if ans == '2':
        result = xena_obj.send_burst_traffic()
    if ans == '3':
        xena_obj.send_cont_traffic()
        Time.sleep(5)
        xena_obj.stop_cont_traffic()
    if ans == '4':
        sys.exit(0)
    for key in result.keys():
        print(key, result[key])
