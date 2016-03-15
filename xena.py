# Copyright 2016 Red Hat Inc & Xena Networks.
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
#
# Contributors:
#   Rick Alongi, Red Hat Inc.
#   Amit Supugade, Red Hat Inc.
#   Dan Amzulescu, Xena Networks
#   Christian Trautman, Red Hat Inc.

"""
Xena Traffic Generator Model
"""

# TODO CT List of things that need to be completed
# 1. Need back to back implementation
# 2. Need to determine what multistream is
# 3. Need to implement fps into api methods.

# VSPerf imports
from conf import settings
from results_constants import ResultsConstants
from trafficgenhelper import TRAFFIC_DEFAULTS, merge_spec, Back2BackResult
# import trafficgen

# python imports
import binascii
import inspect
import logging
import subprocess
import sys
import time as Time
import xml.etree.ElementTree as ET
from collections import OrderedDict

# XenaDriver
import XenaDriver
from XenaDriver import line_percentage
from xena_json import XenaJSON

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

    def __init__(self, debug=False):
        self.mono_pipe = None
        self.xmanager = None
        self._port0 = None
        self._port1 = None
        self._params = {}
        self._xsocket = None
        self._duration = None
        self.debug = debug
        self.tx_stats = None
        self.rx_stats = None

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
    def _create_throughput_result(root):
        """
        :return:
        """
        throughput_test = False
        back2back_test = False
        # get the calling method so we know how to return the stats
        caller = inspect.stack()[1][3]
        if 'throughput' in caller:
            throughput_test = True
        elif 'back2back' in caller:
            back2back_test = True
        else:
            raise NotImplementedError(
                "Unknown implementation for result return")

        if throughput_test:
            results = OrderedDict()
            results[ResultsConstants.THROUGHPUT_RX_FPS] = int(
                root[0][1][0][1].get('PortRxPps'))
            results[ResultsConstants.THROUGHPUT_RX_MBPS] = int(
                root[0][1][0][1].get('PortRxBpsL1')) / 1000
            results[ResultsConstants.THROUGHPUT_RX_PERCENT] = (
                100 - int(root[0][1][0].get('TotalLossRatioPcnt'))) * float(
                    root[0][1][0].get('TotalTxRatePcnt'))/100
            results[ResultsConstants.TX_RATE_FPS] = root[0][1][0].get(
                'TotalTxRateFps')
            results[ResultsConstants.TX_RATE_MBPS] = float(
                root[0][1][0].get('TotalTxRateBpsL1'))/1000
            results[ResultsConstants.TX_RATE_PERCENT] = root[0][1][0].get(
                'TotalTxRatePcnt')
            results[ResultsConstants.MIN_LATENCY_NS] = root[0][1][0][0].get(
                'MinLatency')
            results[ResultsConstants.MAX_LATENCY_NS] = root[0][1][0][0].get(
                'MaxLatency')
            results[ResultsConstants.AVG_LATENCY_NS] = root[0][1][0][0].get(
                'AvgLatency')
        elif back2back_test:
            results = Back2BackResult

            # :returns: Named tuple of Rx Throughput (fps),
            # Rx Throughput (mbps),
            # Tx Rate (% linerate), Rx Rate (% linerate), Tx Count (frames),
            # Back to Back Count (frames), Frame Loss (frames), Frame Loss (%)

            results.rx_fps = int(
                root[0][1][0][1].get('PortRxPps'))
            results.rx_mbps = int(
                root[0][1][0][1].get('PortRxBpsL1')) / 1000
            results.rx_percent = (
                100 - int(root[0][1][0].get('TotalLossRatioPcnt'))) * float(
                    root[0][1][0].get('TotalTxRatePcnt'))/100
            results.tx_count = root[0][1][0].get(
                'TotalTxRateFps')
            results.tx_percent = root[0][1][0].get(
                'TotalTxRatePcnt')

        return results

    def _create_api_result(self):
        """
        Create result dictionary per trafficgen specifications. If stats are
        not available return values of 0.
        :return: ResultsConstants as dictionary
        """
        # Handle each case of statistics based on if the data is available.
        # This prevents uncaught exceptions when the stats aren't available.
        result_dict = OrderedDict()
        if self.tx_stats.data.get(self.tx_stats.pt_stream_keys[0]):
            result_dict[ResultsConstants.TX_FRAMES] = self.tx_stats.data[
                self.tx_stats.pt_stream_keys[0]]['packets']
            result_dict[ResultsConstants.TX_RATE_FPS] = self.tx_stats.data[
                self.tx_stats.pt_stream_keys[0]]['pps']
            result_dict[ResultsConstants.TX_RATE_MBPS] = self.tx_stats.data[
                self.tx_stats.pt_stream_keys[0]]['bps'] / 1000
            result_dict[ResultsConstants.TX_BYTES] = self.tx_stats.data[
                self.tx_stats.pt_stream_keys[0]]['bytes']
            result_dict[ResultsConstants.TX_RATE_PERCENT] = line_percentage(
                self._port0, self.tx_stats, self._duration,
                self._params['traffic']['l2']['framesize'])
        else:
            self._logger.error('Transmit stats not available.')
            result_dict[ResultsConstants.TX_FRAMES] = 0
            result_dict[ResultsConstants.TX_RATE_FPS] = 0
            result_dict[ResultsConstants.TX_RATE_MBPS] = 0
            result_dict[ResultsConstants.TX_BYTES] = 0
            result_dict[ResultsConstants.TX_RATE_PERCENT] = 0

        if self.rx_stats.data.get('pr_tpldstraffic'):
            result_dict[ResultsConstants.RX_FRAMES] = self.rx_stats.data[
                'pr_tpldstraffic']['0']['packets']
            result_dict[
                ResultsConstants.THROUGHPUT_RX_FPS] = self.rx_stats.data[
                    'pr_tpldstraffic']['0']['pps']
            result_dict[
                ResultsConstants.THROUGHPUT_RX_MBPS] = self.rx_stats.data[
                    'pr_tpldstraffic']['0']['bps'] / 1000
            result_dict[ResultsConstants.RX_BYTES] = self.rx_stats.data[
                'pr_tpldstraffic']['0']['bytes']
            result_dict[
                ResultsConstants.THROUGHPUT_RX_PERCENT] = line_percentage(
                    self._port1, self.rx_stats, self._duration,
                    self._params['traffic']['l2']['framesize'])
        else:
            result_dict[ResultsConstants.RX_FRAMES] = 0
            result_dict[ResultsConstants.THROUGHPUT_RX_FPS] = 0
            result_dict[ResultsConstants.THROUGHPUT_RX_MBPS] = 0
            result_dict[ResultsConstants.RX_BYTES] = 0
            result_dict[ResultsConstants.THROUGHPUT_RX_PERCENT] = 0

        if self.rx_stats.data.get('pr_tplderrors'):
            result_dict[ResultsConstants.PAYLOAD_ERR] = self.rx_stats.data[
                'pr_tplderrors']['0']['pld']
            result_dict[ResultsConstants.SEQ_ERR] = self.rx_stats.data[
                'pr_tplderrors']['0']['seq']
        else:
            result_dict[ResultsConstants.PAYLOAD_ERR] = 0
            result_dict[ResultsConstants.SEQ_ERR] = 0

        if self.rx_stats.data.get('pr_tpldlatency'):
            result_dict[ResultsConstants.MIN_LATENCY_NS] = self.rx_stats.data[
                'pr_tpldlatency']['0']['min']
            result_dict[ResultsConstants.MAX_LATENCY_NS] = self.rx_stats.data[
                'pr_tpldlatency']['0']['max']
            result_dict[ResultsConstants.AVG_LATENCY_NS] = self.rx_stats.data[
                'pr_tpldlatency']['0']['avg']
        else:
            result_dict[ResultsConstants.MIN_LATENCY_NS] = 0
            result_dict[ResultsConstants.MAX_LATENCY_NS] = 0
            result_dict[ResultsConstants.AVG_LATENCY_NS] = 0

        return result_dict

    def _build_packet_header(self):
        """
        Build a packet header based on traffic profile using scapy external
        libraries.
        :return: packet header in hex
        """
        layer2 = inet.Ether(src=self._params['traffic']['l2']['srcmac'],
                            dst=self._params['traffic']['l2']['dstmac'])
        layer3 = inet.IP(src=self._params['traffic']['l3']['srcip'],
                         dst=self._params['traffic']['l3']['dstip'],
                         proto=self._params['traffic']['l3']['proto'])
        if self._params['traffic']['vlan']['enabled']:
            vlan = inet.Dot1Q(vlan=self._params['traffic']['vlan']['id'],
                              prio=self._params['traffic']['vlan']['priority'],
                              id=self._params['traffic']['vlan']['cfi'])
        else:
            vlan = None
        packet = layer2/vlan/layer3 if vlan else layer2/layer3
        packet_bytes = bytes(packet)
        packet_hex = '0x' + binascii.hexlify(packet_bytes).decode('utf-8')
        return packet_hex

    def _setup_xml_config(self, trials, loss_rate, testtype=None,
                          multi_stream=None):
        """
        Create a 2bUsed xml file that will be used for xena2544.exe execution.
        :param trials: Number of trials
        :param loss_rate: The acceptable loss rate as float
        :param testtype: Either '2544_b2b' or '2544_throughput' as string
        :param multi_stream: This is changing, do not use
        :return: None
        """
        # enable micro TPLD if byte size is 64 with vlan
        if (self._params['traffic']['vlan']['enabled'] and
                self._params['traffic']['l2']['framesize'] == 64):
            tpld = True
        else:
            tpld = False
        try:
            j_file = XenaJSON('./profiles/baseconfig.x2544')
            j_file.set_test_options(
                packet_sizes=self._params['traffic']['l2']['framesize'],
                iterations=trials, loss_rate=loss_rate,
                duration=self._duration, micro_tpld=tpld)
            if testtype == '2544_throughput':
                j_file.enable_throughput_test()
            elif testtype == '2544_b2b':
                j_file.enable_back2back_test()

            j_file.set_header_layer2(
                dst_mac=self._params['traffic']['l2']['dstmac'],
                src_mac=self._params['traffic']['l2']['srcmac'])
            j_file.set_header_layer3(
                src_ip=self._params['traffic']['l3']['srcip'],
                dst_ip=self._params['traffic']['l3']['dstip'],
                protocol=self._params['traffic']['l3']['proto'])
            if self._params['traffic']['vlan']['enabled']:
                j_file.set_header_vlan(
                    vlan_id=self._params['traffic']['vlan']['id'],
                    id=self._params['traffic']['vlan']['cfi'],
                    prio=self._params['traffic']['vlan']['priority'])
            j_file.add_header_segments()
            j_file.write_config()
        except Exception as exc:
            self._logger.exception(
                "Error during Xena XML setup: {}".format(exc))
            raise

    def _start_traffic_api(self, packet_limit):
        """
        Start the Xena traffic using the socket API driver
        :param packet_limit: packet limit for stream, set to -1 for no limit
        :return: None
        """
        if not self.xmanager:
            self.connect()

        if not self._port0:
            self._port0 = self.xmanager.add_module_port(TRAFFICGEN_MODULE1,
                                                        TRAFFICGEN_PORT1)
            if not self._port0:
                self._logger.error("Fail to add port " + str(TRAFFICGEN_PORT1))
                sys.exit(-1)
            self._port0.reserve_port()

        if not self._port1:
            self._port1 = self.xmanager.add_module_port(TRAFFICGEN_MODULE2,
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
        s1_p0.set_packet_limit(packet_limit)

        s1_p0.set_rate_fraction(1000000)
        s1_p0.set_packet_header(self._build_packet_header())
        # TODO Fix the below line to adapt better to the self._params
        s1_p0.set_header_protocol('ETHERNET VLAN IP' if self._params['traffic'][
            'vlan']['enabled'] else 'ETHERNET IP')
        s1_p0.set_packet_length(
            'fixed', self._params['traffic']['l2']['framesize'], 16383)
        s1_p0.set_packet_payload('incrementing', '0x00')
        s1_p0.set_payload_id(0)

        self._port0.set_port_time_limit(self._duration * 1000000)

        if not self._port0.traffic_on():
            self._logger.error(
                "Failure to start traffic. Check settings and retry.")
        Time.sleep(self._duration + 1)

    def _stop_api_traffic(self):
        """
        Stop traffic through the socket API
        :return: Return results from _create_api_result method
        """
        self._port0.traffic_off()

        # getting results
        self.tx_stats = self._port0.get_tx_stats()
        self.rx_stats = self._port1.get_rx_stats()
        return self._create_api_result()

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
        self.xmanager = XenaDriver.XenaManager(self._xsocket, TRAFFICGEN_USER,
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
        self._duration = duration

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(self._params['traffic'],
                                                 traffic)

        self._start_traffic_api(numpkts)
        return self._stop_api_traffic()

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
        self._duration = duration

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(self._params['traffic'],
                                                 traffic)

        self._start_traffic_api(-1)
        return self._stop_api_traffic()

    def start_cont_traffic(self, traffic=None, duration=20):
        """Non-blocking version of 'send_cont_traffic'.

        Start transmission and immediately return. Do not wait for
        results.
        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN tags
        :param duration: Time to wait to receive packets (secs)
        """
        self._duration = duration

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(self._params['traffic'],
                                                 traffic)

        self._start_traffic_api(-1)

    def stop_cont_traffic(self):
        """Stop continuous transmission and return results.
        """
        return self._stop_api_traffic()

    def send_rfc2544_throughput(self, traffic=None, trials=3, duration=20,
                                lossrate=0.0, multistream=False):
        """Send traffic per RFC2544 throughput test specifications.

        Send packets at a variable rate, using ``traffic``
        configuration, until minimum rate at which no packet loss is
        detected is found.

        :param traffic: Detailed "traffic" spec, i.e. IP address, VLAN tags
        :param trials: Number of trials to execute
        :param duration: Per iteration duration
        :param lossrate: Acceptable lossrate percentage
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
        self._duration = duration

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(self._params['traffic'],
                                                 traffic)

        self._setup_xml_config(trials, lossrate, '2544_throughput', multistream)

        args = ["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e", "-r",
                "./", "-u", TRAFFICGEN_USER]
        self.mono_pipe = subprocess.Popen(
            args, stdout=sys.stdout if self.debug else subprocess.PIPE)
        self.mono_pipe.communicate()
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
        self._duration = duration
        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(self._params['traffic'],
                                                 traffic)

        self._setup_xml_config(trials, lossrate, '2544_throughput')

        args = ["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e", "-r",
                "./", "-u", TRAFFICGEN_USER]
        self.mono_pipe = subprocess.Popen(
            args, stdout=sys.stdout if self.debug else subprocess.PIPE)

    def wait_rfc2544_throughput(self):
        """Wait for and return results of RFC2544 test.
        """
        self.mono_pipe.communicate()
        root = ET.parse(r'./xesna2544-report.xml').getroot()
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
        self._duration = duration

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(self._params['traffic'],
                                                 traffic)

        self._setup_xml_config(trials, lossrate, '2544_b2b')

        args = ["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e", "-r",
                "./", "-u", TRAFFICGEN_USER]
        self.mono_pipe = subprocess.Popen(
            args, stdout=sys.stdout if self.debug else subprocess.PIPE)
        self.mono_pipe.communicate()
        root = ET.parse(r'./xena2544-report.xml').getroot()
        # TODO change this to the tuple per docstring
        return Xena._create_throughput_result(root)

    def start_rfc2544_back2back(self, traffic=None, trials=1, duration=20,
                                lossrate=0.0):
        """Non-blocking version of 'send_rfc2544_back2back'.

        Start transmission and immediately return. Do not wait for
        results.
        """
        self._duration = duration

        self._params.clear()
        self._params['traffic'] = self.traffic_defaults.copy()
        if traffic:
            self._params['traffic'] = merge_spec(self._params['traffic'],
                                                 traffic)

        self._setup_xml_config(trials, lossrate, '2544_b2b')

        args = ["mono", "./Xena2544.exe", "-c", "./2bUsed.x2544", "-e", "-r",
                "./", "-u", TRAFFICGEN_USER]
        self.mono_pipe = subprocess.Popen(
            args, stdout=sys.stdout if self.debug else subprocess.PIPE)

    def wait_rfc2544_back2back(self):
        """Wait and set results of RFC2544 test.
        """
        self.mono_pipe.communicate()
        root = ET.parse(r'./xena2544-report.xml').getroot()
        # TODO change per docstring tuple specifications
        return Xena._create_throughput_result(root)


if __name__ == "__main__":
    print("Running Xena VSPerf script UnitTest")
    XENA_OBJ = Xena(debug=True)

    class TestProps(object):
        """
        Simple class for unit testing properties
        """
        def __init__(self, framesize=None, test_duration=10, trials=1):
            """
            Constructor
            :param framesize: framesize
            :param test_duration: duration in sec
            :param trials: number of trials
            :return: TestProps instance
            """
            self.framesize = TRAFFIC_DEFAULTS['l2'][
                'framesize'] if not framesize else framesize
            self.framesizes = [64, 128, 256, 512, 1024, 1500, 9000]
            self.duration = test_duration
            self.trials = trials

        def increase_framesize(self):
            """
            Increase to next framesize
            :return: None
            """
            index = self.framesizes.index(self.framesize)
            try:
                self.framesize = self.framesizes[index + 1]
            except IndexError:
                self.framesize = self.framesizes[-1]

        def decrease_framesize(self):
            """
            Decrease to previous framesize
            :return: None
            """
            index = self.framesizes.index(self.framesize)
            self.framesize = self.framesizes[index - 1] if index > 0 \
                else self.framesizes[0]

        def set_duration(self):
            """
            Prompt user for duration
            :return: None
            """
            res = input("Enter a test time in seconds:")
            self.duration = int(res)

        def set_trials(self):
            """
            Prompt user for trial number
            :return: None
            """
            res = input("Enter number of trials:")
            self.trials = int(res)

    def toggle_debug():
        """
        Toggle debug
        :return: None
        """
        XENA_OBJ.debug = False if XENA_OBJ.debug else True

    PROPS = TestProps()

    TESTMETHODS = {
        1: [XENA_OBJ.send_rfc2544_throughput],
        2: [XENA_OBJ.start_rfc2544_throughput,
            XENA_OBJ.wait_rfc2544_throughput],
        3: [XENA_OBJ.send_burst_traffic],
        4: [XENA_OBJ.send_cont_traffic],
        5: [XENA_OBJ.start_cont_traffic, XENA_OBJ.stop_cont_traffic],
        6: [XENA_OBJ.send_rfc2544_back2back],
        7: [XENA_OBJ.start_rfc2544_back2back, XENA_OBJ.wait_rfc2544_back2back],
        8: [PROPS.decrease_framesize],
        9: [PROPS.increase_framesize],
        10: [PROPS.set_duration],
        11: [PROPS.set_trials],
        12: [toggle_debug],
        13: [sys.exit],
    }

    def go_menu():
        """
        Run the Unittest method menu
        :return: None
        """
        print("Packet size: {} | duration: {}".format(PROPS.framesize,
                                                      PROPS.duration))
        print("Trials for 2544 tests: {}".format(PROPS.trials))
        print("DEBUG is {}".format('ON' if XENA_OBJ.debug else 'OFF'))
        print("What method to test?")
        for k in sorted(TESTMETHODS.keys()):
            line = "{}. ".format(k)
            for func in TESTMETHODS[k]:
                line += "{}/".format(func.__name__)
            line = line.rstrip('/')
            print(line)
        ans = 0
        while ans not in TESTMETHODS.keys():
            ans = input("> ")
            try:
                if len(TESTMETHODS.keys()) >= int(ans) > 0:
                    break
                else:
                    print("!!Invalid entry!!")
            except ValueError:
                print("!!Invalid entry!!")

        for func in TESTMETHODS[int(ans)]:
            if func.__name__ in XENA_OBJ.__dir__():
                kwargs = dict()
                if 'traffic' in inspect.getargspec(func)[0]:
                    params = {
                        'l2': {
                            'framesize': PROPS.framesize,
                        },
                    }
                    kwargs['traffic'] = params
                if 'trials' in inspect.getargspec(func)[0]:
                    kwargs['trials'] = PROPS.trials
                if 'duration' in inspect.getargspec(func)[0]:
                    kwargs['duration'] = PROPS.duration
                result = func(**kwargs)
                print(result)
            else:
                func()

    while True:
        go_menu()

