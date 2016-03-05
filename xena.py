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

# TODO CT List of things that need to be completed
# 1. Need back to back implementation
# 2. Need to do L1 bitrate calculation
# 3. Need to determine what multistream is
# 4. Need to get latency values from 2544 output / currently showing as None
# 5. Need to implement fps into api methods.

# VSPerf imports
from conf import settings
from results_constants import ResultsConstants
from trafficgenhelper import TRAFFIC_DEFAULTS, merge_spec
# import trafficgen

# python imports
import binascii
import logging
import subprocess
import sys
import time as Time
import xml.etree.ElementTree as ET
from collections import OrderedDict

# XenaDriver
import XenaDriver
from XenaXML import XMLConfig

# scapy imports
# pip install scapy to install on python 2.x
# pip install scapy-python3 for python 3.x
import scapy.layers.inet as inet

settings.load_from_dir('conf')
TRAFFICGEN_IP = settings.getValue('TRAFFICGEN_XENA_IP')
TRAFFICGEN_PORT1 = settings.getValue('TRAFFICGEN_XENA_PORT1')
TRAFFICGEN_PORT2 = settings.getValue('TRAFFICGEN_XENA_PORT2')
TRAFFICGEN_USER = settings.getValue('TRAFFICGEN_XENA_USER')
TRAFFICGEN_PASSWORD = settings.getValue('TRAFFICGEN_XENA_PASSWORD')
TRAFFICGEN_MODULE1 = settings.getValue('TRAFFICGEN_XENA_MODULE1')
TRAFFICGEN_MODULE2 = settings.getValue('TRAFFICGEN_XENA_MODULE2')

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
        self._port0 = None
        self._port1 = None
        self._params = {}
        self._xsocket = None

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

    @staticmethod
    def build_test_packet():
        """
        Build a packet header based on traffic profile using scapy external
        libraries.
        """
        l2 = inet.Ether(src=TRAFFIC_DEFAULTS['l2']['srcmac'],
                        dst=TRAFFIC_DEFAULTS['l2']['dstmac'])
        l3 = inet.IP(src=TRAFFIC_DEFAULTS['l3']['srcip'],
                     dst=TRAFFIC_DEFAULTS['l3']['dstip'],
                     proto=TRAFFIC_DEFAULTS['l3']['proto'])
        if TRAFFIC_DEFAULTS['vlan']['enabled']:
            vlan = inet.Dot1Q(vlan=TRAFFIC_DEFAULTS['vlan']['id'],
                              prio=TRAFFIC_DEFAULTS['vlan']['priority'],
                              id=TRAFFIC_DEFAULTS['vlan']['cfi'])
        else:
            vlan = None
        packet = l2/vlan/l3 if vlan else l2/l3
        packet_bytes = bytes(packet)
        packet_hex = '0x' + binascii.hexlify(packet_bytes).decode('utf-8')
        return packet_hex
        # TODO VLANS doesn't seem to work yet..

    @staticmethod
    def _create_throughput_result(root):
        """
        :return:
        """
        result_dict = OrderedDict()
        # TODO get these parameters
        # result_dict[ResultsConstants.THROUGHPUT_RX_FPS] = ?
        # result_dict[ResultsConstants.THROUGHPUT_RX_MBPS] = ?
        result_dict[ResultsConstants.THROUGHPUT_RX_PERCENT] = (
            100 - int(root[0][1][0].get(
                    'TotalLossRatioPcnt'))) * float(root[0][1][0].get(
                        'TotalTxRatePcnt'))/100
        result_dict[ResultsConstants.TX_RATE_FPS] = root[0][1][0].get(
                'TotalTxRateFps')
        result_dict[ResultsConstants.TX_RATE_MBPS] = float(root[0][1][0].get(
                'TotalTxRateBpsL2'))/1000
        result_dict[ResultsConstants.TX_RATE_PERCENT] = root[0][1][0].get(
                'TotalTxRatePcnt')
        result_dict[ResultsConstants.MIN_LATENCY_NS] = root[0][1][0][0].get(
            'MinLatency')
        result_dict[ResultsConstants.MAX_LATENCY_NS] = root[0][1][0][0].get(
            'MaxLatency')
        result_dict[ResultsConstants.AVG_LATENCY_NS] = root[0][1][0][0].get(
            'AvgLatency')

        return result_dict

    def _setup_xml_config(self, trials, duration, loss_rate, testtype=None,
                          multi_stream=None):
        try:
            # layer 2 info
            framesize = self._params['traffic']['l2']['framesize']
            srcmac = self._params['traffic']['l2']['srcmac']
            dstmac = self._params['traffic']['l2']['dstmac']
            vlanid = self._params['traffic']['vlan']['id']
            vlanpri = self._params['traffic']['vlan']['priority']
            vlancfi = self._params['traffic']['vlan']['cfi']

            # layer 3 info
            srcip = self._params['traffic']['l3']['srcip']
            dstip = self._params['traffic']['l3']['dstip']

            # layer 4 info
            proto = self._params['traffic']['l3']['proto']

            # TODO Remove this. Debug for quicker testing.
            trials = 1
            duration = 5

            # Read configuration file to variable
            xml = XMLConfig('./profiles/baseconfig.x2544')

            # set XML data
            xml.trials = trials
            xml.duration = duration
            xml.loss_rate = loss_rate
            xml.custom_packet_sizes = [framesize]
            xml.throughput_enable = (True if testtype == '2544_throughput'
                                     else False)
            xml.back2back_enable = True if testtype == '2544_b2b' else False

            xml.build_l2_header(dst_mac=dstmac, src_mac=srcmac)
            if srcip != '0.0.0.0' or dstip != '0.0.0.0':
                xml.build_l3_header_ip4(src_ip=srcip, dst_ip=dstip,
                                        protocol=proto)
            if self._params['traffic']['vlan']['enabled']:
                xml.build_vlan_header(vlan_id=vlanid, id=vlancfi, prio=vlanpri)

            xml.add_header_segments()
            xml.write_config()
            xml.write_file('./2bUsed.x2544')
        except Exception as e:
            self._logger("Error during Xena XML setup: {}".format(e))
            raise

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
        self.xm = XenaDriver.XenaManager(self._xsocket, TRAFFICGEN_USER,
                                         TRAFFICGEN_PASSWORD)

    def disconnect(self):
        """Disconnect from the traffic generator.

        As with :func:`connect`, this function is optional.

        Where implemented, this function should raise an exception on
        failure.

        :returns: None
        """
        self._xsocket.disconnect()

    def send_burst_traffic(self, traffic=None, numpkts=100, duration=20):
        """Send a burst of traffic.

        Send a ``numpkts`` packets of traffic, using ``traffic``
        configuration, with a timeout of ``time``.

        Attributes:
        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN tags
        :param numpkts: Number of packets to send
        :param duration: Time to wait to receive packets

        :returns: dictionary of strings with following data:
            - List of Tx Frames,
            - List of Rx Frames,
            - List of Tx Bytes,
            - List of List of Rx Bytes,
            - Payload Errors and Sequence Errors.
        """

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        if not self.xm:
            self.connect()

        if not self._port0:
            self._port0 = self.xm.add_module_port(TRAFFICGEN_MODULE1,
                                                  TRAFFICGEN_PORT1)
            if not self._port0:
                self._logger.error("Fail to add port " + str(TRAFFICGEN_PORT1))
                sys.exit(-1)
            self._port0.reserve_port()

        if not self._port1:
            self._port1 = self.xm.add_module_port(TRAFFICGEN_MODULE2,
                                                  TRAFFICGEN_PORT2)
            if not self._port1:
                self._logger.error("Fail to add port" + str(TRAFFICGEN_PORT2))
                sys.exit(-1)
            self._port1.reserve_port()

        # Clear port configuration for a clean start
        self._port0.reset_port()
        self._port1.reset_port()

        # Add one stream for port 0
        s1_p0 = self._port0.add_stream()
        s1_p0.set_on()

        # setup stream params
        s1_p0.set_packet_header(self.build_test_packet())
        s1_p0.set_header_protocol('ETHERNET VLAN IP')
        s1_p0.set_packet_length(
                'fixed', self._params['traffic']['l2']['framesize'], 16383)
        s1_p0.set_packet_payload('incrementing', '0x00')
        s1_p0.set_packet_limit(numpkts)
        s1_p0.set_rate_fraction(1000000)
        # PS_RATEPPS [SID] PPS if fps
        s1_p0.set_payload_id(0)
        self._port0.set_port_time_limit(duration * 1000000)  # automatic stop

        self._port0.clear_stats()
        self._port1.clear_stats()

        # start/[wait]/stop the traffic
        if not self._port0.traffic_on():
            self._logger.error(
                    "Failure to start traffic. Check settings and retry.")
            sys.exit(1)
        Time.sleep(duration + 1)
        self._port0.traffic_off()

        # getting results
        tx_stats = self._port0.get_tx_stats()
        rx_stats = self._port1.get_rx_stats()

        result_dict = OrderedDict()

        result_dict[ResultsConstants.TX_FRAMES] = tx_stats.data[
            tx_stats.time][tx_stats.pt_stream_keys[0]]['packets']
        result_dict[ResultsConstants.RX_FRAMES] = rx_stats.data[
            rx_stats.time]['pr_tpldstraffic']['0']['packets']
        result_dict[ResultsConstants.TX_BYTES] = tx_stats.data[
            tx_stats.time][tx_stats.pt_stream_keys[0]]['bytes']
        result_dict[ResultsConstants.RX_BYTES] = rx_stats.data[
            rx_stats.time]['pr_tpldstraffic']['0']['bytes']
        result_dict[ResultsConstants.PAYLOAD_ERR] = rx_stats.data[
            rx_stats.time]['pr_tplderrors']['0']['pld']
        result_dict[ResultsConstants.SEQ_ERR] = rx_stats.data[
            rx_stats.time]['pr_tplderrors']['0']['seq']

        return result_dict

    def send_cont_traffic(self, traffic=None, duration=20, multistream=False):
        """Send a continuous flow of traffic.r

        Send packets at ``framerate``, using ``traffic`` configuration,
        until timeout ``time`` occurs.

        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN tags
        :param duration: Time to wait to receive packets (secs)
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
        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        if not self.xm:
            self.connect()

        if not self._port0:
            self._port0 = self.xm.add_module_port(TRAFFICGEN_MODULE1,
                                                  TRAFFICGEN_PORT1)
            if not self._port0:
                self._logger.error("Fail to add port " + str(TRAFFICGEN_PORT1))
                sys.exit(-1)
            self._port0.reserve_port()

        if not self._port1:
            self._port1 = self.xm.add_module_port(TRAFFICGEN_MODULE2,
                                                  TRAFFICGEN_PORT2)
            if not self._port1:
                self._logger.error("Fail to add port" + str(TRAFFICGEN_PORT2))
                sys.exit(-1)
            self._port1.reserve_port()

        # Clear port configuration for a clean start
        self._port0.reset_port()
        self._port1.reset_port()
        self._port0.clear_stats()
        self._port1.clear_stats()

        s1_p0 = self._port0.add_stream()
        s1_p0.set_on()
        s1_p0.set_packet_limit(-1)  # for continuous flow

        s1_p0.set_rate_fraction(1000000)
        s1_p0.set_packet_header(self.build_test_packet())
        # TODO Fix the below line to adapt better to the self._params
        s1_p0.set_header_protocol('ETHERNET VLAN IP' if self._params['traffic'][
            'vlan']['enabled'] else 'ETHERNET IP')
        s1_p0.set_packet_length(
                'fixed', self._params['traffic']['l2']['framesize'], 16383)
        s1_p0.set_packet_payload('incrementing', '0x00')
        s1_p0.set_payload_id(0)

        self._port0.set_port_time_limit(duration*1000000)  # automatic stop

        # start the traffic
        if not self._port0.traffic_on():
            self._logger.error(
                    "Failure to start traffic. Check settings and retry.")
            sys.exit(1)
        Time.sleep(duration + 1)

        # getting results
        tx_stats = self._port0.get_tx_stats()
        rx_stats = self._port1.get_rx_stats()

        # TODO need to implement multistream stat collection CT
        result_dict = OrderedDict()
        result_dict[ResultsConstants.TX_RATE_FPS] = tx_stats.data[
            tx_stats.time][tx_stats.pt_stream_keys[0]]['pps']
        result_dict[ResultsConstants.THROUGHPUT_RX_FPS] = rx_stats.data[
            rx_stats.time]['pr_tpldstraffic']['0']['pps']
        result_dict[ResultsConstants.TX_RATE_MBPS] = tx_stats.data[
            tx_stats.time][tx_stats.pt_stream_keys[0]]['bps'] * 1000
        result_dict[ResultsConstants.THROUGHPUT_RX_MBPS] = rx_stats.data[
            rx_stats.time]['pr_tpldstraffic']['0']['bps'] * 1000

        # TODO: Find port speed and % linerate out of it (based on framesize)
        # PT_STREAM [SID] BPS PPS BYTES PACKETS
        # PT_STREAM [SID] ?
        # PR_TPLDTRAFFIC [TID] ?
        # bitrateL1 = bitRateL2 + frameRate * interFrameGap * 8;
        # The bitRateL2 – is the L1bits of the packets(FPS*PacketSize) the frameRate * InterFrameGap * 8
        # Is the completingL1 of the IFG`s (the way we refer to it…it includes the preamble as well).
        # result['Tx Throughput % linerate'] = tx_stats[pt_stream_0][0]
        # result['Rx Throughput % linerate'] = rx_stats[pr_tpldstraffic][0][0]

        result_dict[ResultsConstants.MIN_LATENCY_NS] = rx_stats.data[
            rx_stats.time]['pr_tpldlatency']['0']['min']
        result_dict[ResultsConstants.MAX_LATENCY_NS] = rx_stats.data[
            rx_stats.time]['pr_tpldlatency']['0']['max']
        result_dict[ResultsConstants.AVG_LATENCY_NS] = rx_stats.data[
            rx_stats.time]['pr_tpldlatency']['0']['avg']

        return result_dict

    def start_cont_traffic(self, traffic=None, duration=20):
        """Non-blocking version of 'send_cont_traffic'.

        Start transmission and immediately return. Do not wait for
        results.
        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN tags
        :param duration: Time to wait to receive packets (secs)
        """

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        if not self.xm:
            self.connect()

        if not self._port0:
            self._port0 = self.xm.add_module_port(TRAFFICGEN_MODULE1,
                                              TRAFFICGEN_PORT1)
            if not self._port0:
                self._logger.error("Fail to add port " + str(TRAFFICGEN_PORT1))
                sys.exit(-1)
            self._port0.reserve_port()

        if not self._port1:
            self._port1 = self.xm.add_module_port(TRAFFICGEN_MODULE2,
                                                  TRAFFICGEN_PORT2)
            if not self._port1:
                self._logger.error("Fail to add port" + str(TRAFFICGEN_PORT2))
                sys.exit(-1)
            self._port1.reserve_port()

        # Clear port configuration for a clean start
        self._port0.reset_port()
        self._port1.reset_port()

        s1_p0 = self._port0.add_stream()
        s1_p0.set_on()
        s1_p0.set_packet_limit(-1)  # for continues flow

        s1_p0.set_rate_fraction(1000000)
        self._port0.set_port_time_limit(duration * 1000000)
        s1_p0.set_packet_header(self.build_test_packet())
        # TODO Fix the below line to adapt better to the self._params
        s1_p0.set_header_protocol('ETHERNET VLAN IP' if self._params['traffic'][
            'vlan']['enabled'] else 'ETHERNET IP')
        s1_p0.set_packet_length(
                'fixed', self._params['traffic']['l2']['framesize'], 16383)
        s1_p0.set_packet_payload('incrementing', '0x00')

        s1_p0.set_payload_id(0)

        self._port0.clear_stats()
        self._port1.clear_stats()

        # start the traffic and return
        if not self._port0.traffic_on():
            self._logger.error(
                    "Failure to start traffic. Check settings and retry.")
            sys.exit(1)

    def stop_cont_traffic(self):
        """Stop continuous transmission and return results.
        """
        self._port0 = self.xm.get_module_port(TRAFFICGEN_MODULE1,
                                              TRAFFICGEN_PORT1)
        self._port0.traffic_off()

        # getting results
        tx_stats = self._port0.get_tx_stats()
        rx_stats = self._port1.get_rx_stats()

        # TODO need to implement multistream stat collection CT
        result_dict = OrderedDict()

        result_dict[ResultsConstants.TX_RATE_FPS] = tx_stats.data[
            tx_stats.time][tx_stats.pt_stream_keys[0]]['pps']
        result_dict[ResultsConstants.THROUGHPUT_RX_FPS] = rx_stats.data[
            rx_stats.time]['pr_tpldstraffic']['0']['pps']
        result_dict[ResultsConstants.TX_RATE_MBPS] = tx_stats.data[
            tx_stats.time][tx_stats.pt_stream_keys[0]]['bps'] * 1000
        result_dict[ResultsConstants.THROUGHPUT_RX_MBPS] = rx_stats.data[
            rx_stats.time]['pr_tpldstraffic']['0']['bps'] * 1000

        # TODO: Find port speed and % linerate out of it (based on framesize)
        # result['Tx Throughput % linerate'] = tx_stats[pt_stream_0][0]
        # result['Rx Throughput % linerate'] = rx_stats[pr_tpldstraffic][0][0]

        result_dict[ResultsConstants.MIN_LATENCY_NS] = rx_stats.data[
            rx_stats.time]['pr_tpldlatency']['0']['min']
        result_dict[ResultsConstants.MAX_LATENCY_NS] = rx_stats.data[
            rx_stats.time]['pr_tpldlatency']['0']['max']
        result_dict[ResultsConstants.AVG_LATENCY_NS] = rx_stats.data[
            rx_stats.time]['pr_tpldlatency']['0']['avg']

        return result_dict

    def send_rfc2544_throughput(self, traffic=None, trials=3, duration=20,
                                lossrate=0.0, multistream=False):

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        self._setup_xml_config(trials, duration, lossrate, '2544_throughput',
                               multistream)

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

        args = ["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e", "-r",
                "./", "-u", TRAFFICGEN_USER]
        subprocess.call(args)
        root = ET.parse(r'./xena2544-report.xml').getroot()
        return Xena._create_throughput_result(root)

    def start_rfc2544_throughput(self, traffic=None, trials=3, duration=20,
                                 lossrate=0.0):
        """Non-blocking version of 'send_rfc2544_throughput'.

        Start transmission and immediately return. Do not wait for
        results.
        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN tags
        :param trials: Number of trials to execute
        :param duration: Per iteration duration
        :param lossrate: Acceptable lossrate percentage
        """

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        self._setup_xml_config(trials, duration, lossrate, '2544_throughput')
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

        args = ["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e", "-r",
                "./", "-u", TRAFFICGEN_USER]
        self.mono_pipe = subprocess.Popen(args)

    def wait_rfc2544_throughput(self):
        """Wait for and return results of RFC2544 test.
        """
        self.mono_pipe.communicate()[0]
        root = ET.parse(r'./xena2544-report.xml').getroot()
        return Xena._create_throughput_result(root)

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

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        self._setup_xml_config(trials, duration, lossrate, '2544_b2b')

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

        args = ["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e", "-r",
                "./", "-u", TRAFFICGEN_USER]
        subprocess.call(args)
        root = ET.parse(r'./xena2544-report.xml').getroot()
        # TODO change this to the tuple per docstring
        return Xena._create_throughput_result(root)

    def start_rfc2544_back2back(self, traffic=None, trials=1, duration=20,
                                lossrate=0.0):
        """Non-blocking version of 'send_rfc2544_back2back'.

        Start transmission and immediately return. Do not wait for
        results.
        """

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(
                    self._params['traffic'], traffic)

        self._setup_xml_config(trials, duration, lossrate, '2544_b2b')
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

        args = ["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e", "-r",
                "./", "-u", TRAFFICGEN_USER]
        self.mono_pipe = subprocess.Popen(args)

    def wait_rfc2544_back2back(self):
        """Wait and set results of RFC2544 test.
        """
        self.mono_pipe.communicate()[0]
        root = ET.parse(r'./xena2544-report.xml').getroot()
        # TODO change per docstring tuple specifications
        return Xena._create_throughput_result(root)


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
    print("2. start/stop rfc2544 throughput")
    print("3. send_burst_traffic")
    print("4. send_cont_traffic/stop_cont_traffic")
    print("5. Perform each in order.")
    print("6. Quit")
    ans = 0
    while ans not in ('1', '2', '3', '4'):
        ans = input("> ")
        try:
            if 6 > int(ans) > 0:
                break
            else:
                print("!!Invalid entry!!")
        except TypeError:
            print("!!Invalid entry!!")
    if ans == '1':
        result = xena_obj.send_rfc2544_throughput()
    elif ans == '2':
        xena_obj.start_rfc2544_throughput()
        Time.sleep(2)
        xena_obj.wait_rfc2544_throughput()
    elif ans == '3':
        result = xena_obj.send_burst_traffic()
    elif ans == '4':
        xena_obj.start_cont_traffic()
        Time.sleep(5)
        result = xena_obj.stop_cont_traffic()
    elif ans == '5':
        result = xena_obj.send_rfc2544_throughput()
        for key in result.keys():
            print(key, result[key])
        result = xena_obj.send_burst_traffic()
        for key in result.keys():
            print(key, result[key])
        xena_obj.start_cont_traffic()
        Time.sleep(5)
        result = xena_obj.stop_cont_traffic()
        for key in result.keys():
            print(key, result[key])
        result = xena_obj.send_cont_traffic()
    elif ans == '6':
        sys.exit(0)
    for key in result.keys():
        print(key, result[key])
