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

import base64
import json
import logging

import scapy.layers.inet as inet

_logger = logging.getLogger(__name__)

# TODO Document (docstring) and comment this file


class XMLConfig(object):
    def __init__(self, xml_path='./profiles/baseconfig.x2544'):

        self.xml_path = xml_path

        self.file_data = dict()

        # Test config info
        self.trials = None
        self.duration = None
        self.loss_rate = None

        # Xena Chassis info
        self.chassisIP = None
        self.chassisPwd = None

        # Physical Xena info
        self.module1 = None
        self.module2 = None
        self.port1 = None
        self.port2 = None
        self.port1_UID = None
        self.port2_UID = None
        self.chassisID = None

        # header info
        self.l2 = None
        self.l3 = None
        self.vlan = None
        self.segments = list()

        # Read the xml file and configuration settings
        self.read_file()
        self.read_config()

    def add_header_segments(self):
        packet = self.create_packet_header()
        header_pos = 0
        if self.l2:
            value = str(encode_byte_array(bytes(packet)[:len(self.l2)]))
            d = {"SegmentType": "ETHERNET",
                 "SegmentValue": value,
                 "ItemID": "bdf7bd1c-4634-4fb5-909b-6200237e2647",
                 "ParentID": "",
                 "Label": ""}
            self.segments.append(d)
            header_pos += len(self.l2)
        if self.vlan:
            value = str(encode_byte_array(bytes(packet)[header_pos: len(
                self.vlan) + header_pos]))
            d = {"SegmentType": "VLAN",
                 "SegmentValue": value,
                 "ItemID": "51af8770-99c4-4824-885d-990258e2a890",
                 "ParentID": "",
                 "Label": ""}
            self.segments.append(d)
            header_pos += len(self.vlan)
        if self.l3:
            value = str(encode_byte_array(bytes(packet)[header_pos: len(
                self.l3) + header_pos]))
            d = {"SegmentType": "IP",
                 "SegmentValue": value,
                 "ItemID": "1f67026e-0a83-462f-9c43-dd3661754167",
                 "ParentID": "",
                 "Label": ""}
            self.segments.append(d)
            header_pos += len(self.l3)

    def build_l2_header(self, dst_mac='aa:aa:aa:aa:aa:aa',
                        src_mac='bb:bb:bb:bb:bb:bb', **kwargs):
        self.l2 = inet.Ether(dst=dst_mac, src=src_mac, **kwargs)

    def build_l3_header_ip4(self, src_ip='192.168.0.2', dst_ip='192.168.0.3',
                            protocol='UDP', **kwargs):
        self.l3 = inet.IP(src=src_ip, dst=dst_ip, proto=protocol.lower(),
                          **kwargs)

    def build_vlan_header(self, vlan_id=1, **kwargs):
        self.vlan = inet.Dot1Q(vlan=vlan_id, **kwargs)

    def create_packet_header(self):
        packet = inet.Ether()
        if self.l2:
            packet = self.l2
        if self.vlan:
            packet /= self.vlan
        if self.l3:
            packet /= self.l3
        return packet

    def read_config(self):
        try:
            self.chassisIP = self.file_data['ChassisManager']['ChassisList'][
                0]['HostName']
            self.chassisPwd = self.file_data['ChassisManager'][
                'ChassisList'][0]['Password']
            self.duration = self.file_data['TestOptions'][
                'TestTypeOptionMap']['Throughput']['Duration']
            self.loss_rate = self.file_data['TestOptions'][
                'TestTypeOptionMap']['Throughput']['RateIterationOptions'][
                'AcceptableLoss']
            self.module1 = self.file_data['PortHandler']['EntityList'][0][
                'PortRef']['ModuleIndex']
            self.module2 = self.file_data['PortHandler']['EntityList'][1][
                'PortRef']['ModuleIndex']
            self.port1 = self.file_data['PortHandler']['EntityList'][0][
                'PortRef']['PortIndex']
            self.port1_UID = self.file_data['PortHandler']['EntityList'][0][
                'ItemID']
            self.port2 = self.file_data['PortHandler']['EntityList'][1][
                'PortRef']['PortIndex']
            self.port2_UID = self.file_data['PortHandler']['EntityList'][1][
                'ItemID']
            self.trials = self.file_data['TestOptions']['TestTypeOptionMap'][
                'Throughput']['Iterations']
            return True
        except Exception as e:
            _logger.exception(
                'Error in XML file, setting not found: {}'.format(e))
            return False

    def read_file(self):
        try:
            with open(self.xml_path, 'r', encoding='utf-8') as data_file:
                self.file_data = json.loads(data_file.read())
                return True
        except Exception as e:
            _logger.exception('Exception during Xena xml read: {}'.format(e))
            return False

    def write_config(self):
        self.file_data['ChassisManager']['ChassisList'][0][
            'HostName'] = self.chassisIP
        self.file_data['ChassisManager']['ChassisList'][0][
            'Password'] = self.chassisPwd
        self.file_data['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Duration'] = self.duration
        self.file_data['TestOptions']['TestTypeOptionMap']['Throughput'][
            'RateIterationOptions']['AcceptableLoss'] = self.loss_rate
        self.file_data['PortHandler']['EntityList'][0]['PortRef'][
            'ModuleIndex'] = self.module1
        self.file_data['PortHandler']['EntityList'][1]['PortRef'][
            'ModuleIndex'] = self.module2
        self.file_data['PortHandler']['EntityList'][0]['PortRef'][
            'PortIndex'] = self.port1
        self.file_data['PortHandler']['EntityList'][0][
            'ItemID'] = self.port1_UID
        self.file_data['PortHandler']['EntityList'][1]['PortRef'][
            'PortIndex'] = self.port2
        self.file_data['PortHandler']['EntityList'][1][
            'ItemID'] = self.port2_UID
        self.file_data['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Iterations'] = self.trials
        self.file_data['StreamProfileHandler']['EntityList'][0][
            'StreamConfig']['HeaderSegments'] = self.segments

    def write_file(self, output_path):
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(self.file_data, f, indent=2, sort_keys=True,
                          ensure_ascii=True)
            return True
        except Exception as e:
            _logger.exception('Exception during Xena xml write: {}'.format(e))
            return False


def decode_byte_array(enc_str):
    """ Decodes the base64-encoded string to a byte array
        :param enc_str: The base64-encoded string representing a byte array
        :return: The decoded byte array
    """
    dec_string = base64.b64decode(enc_str)
    b = bytearray()
    b.extend(dec_string)
    return b


def encode_byte_array(byte_arr):
    """ Encodes the byte array as a base64-encoded string
    :param byte_arr: A bytearray containing the bytes to convert
    :return: A base64 encoded string
    """
    enc_string = base64.b64encode(bytes(byte_arr))
    return enc_string


if __name__ == "__main__":
    print("Running UnitTest for XenaXML")
    x = XMLConfig()
    x.build_l2_header()
    x.build_l3_header_ip4()
    x.add_header_segments()
    x.write_config()
    x.write_file('./testthis.x2544')

