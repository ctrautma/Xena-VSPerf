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

# TODO Enable Micro TPLD if 64 byte packet and Ethernet / VLAN / IP / UDP

import base64
import json
import logging

import scapy.layers.inet as inet

_logger = logging.getLogger(__name__)


class XMLConfig(object):
    """
    Class to modify and read Xena JSON configuration files.
    """
    def __init__(self, xml_path='./profiles/baseconfig.x2544'):
        """
        Constructor
        :param xml_path: path to JSON file to read. Expected files must have
         two module ports with each port having its own stream config profile.
        :return: XMLConfig object
        """

        self.xml_path = xml_path

        self.file_data = dict()

        # Test config info
        self.trials = None
        self.duration = None
        self.loss_rate = None
        self.custom_packet_sizes = list()

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
        self.segment1 = list()
        self.segment2 = list()

        # Read the xml file and configuration settings
        self.read_file()
        self.read_config()

    def add_header_segments(self):
        """
        Build the header segments to write to the JSON file.
        :return: None
        """
        packet = self.create_packet_header()
        header_pos = 0
        if self.l2:
            packet_bytes = bytes(packet)
            l2 = packet_bytes[:len(self.l2)]
            value = encode_byte_array(l2)
            value = value.decode('utf-8')

            # swap dst and src for opposite port header info
            op_l2 = l2[6:12] + l2[:6] + l2[12:]
            opp_value = encode_byte_array(op_l2)
            opp_value = opp_value.decode('utf-8')

            d = {"SegmentType": "ETHERNET",
                 "SegmentValue": value,
                 "ItemID": "bdf7bd1c-4634-4fb5-909b-6200237e2647",
                 "ParentID": "",
                 "Label": ""}
            self.segment1.append(d)
            d = {"SegmentType": "ETHERNET",
                 "SegmentValue": opp_value,
                 "ItemID": "6cb89923-61aa-4717-a3c0-20a8ad3356bf",
                 "ParentID": "",
                 "Label": ""}
            self.segment2.append(d)
            header_pos += len(self.l2)
        if self.vlan:
            value = bytes(packet)
            value = value[header_pos: len(self.vlan) + header_pos]
            value = encode_byte_array(value)
            value = value.decode('utf-8')
            d = {"SegmentType": "VLAN",
                 "SegmentValue": value,
                 "ItemID": "51af8770-99c4-4824-885d-990258e2a890",
                 "ParentID": "",
                 "Label": ""}
            self.segment1.append(d)
            d['ItemID'] = "3e49313c-20a5-42be-becf-6915aec64bda"
            self.segment2.append(d)
            header_pos += len(self.vlan)
        if self.l3:
            packet_bytes = bytes(packet)
            l3 = packet_bytes[header_pos: len(self.l3) + header_pos]
            value = encode_byte_array(l3)
            value = value.decode('utf-8')

            # swap dst and src for opposite port header info
            op_l3 = l3[:12] + l3[16:20] + l3[12:16] + l3[20:]
            opp_value = encode_byte_array(op_l3)
            opp_value = opp_value.decode('utf-8')

            d = {"SegmentType": "IP",
                 "SegmentValue": value,
                 "ItemID": "1f67026e-0a83-462f-9c43-dd3661754167",
                 "ParentID": "",
                 "Label": ""}
            self.segment1.append(d)
            d = {"SegmentType": "IP",
                 "SegmentValue": opp_value,
                 "ItemID": "fe797ed1-f29b-4050-85d4-db5ef4f08f2d",
                 "ParentID": "",
                 "Label": ""}
            self.segment2.append(d)
            header_pos += len(self.l3)

    def build_l2_header(self, dst_mac='aa:aa:aa:aa:aa:aa',
                        src_mac='bb:bb:bb:bb:bb:bb', **kwargs):
        """
        Build a scapy Ethernet L2 object
        :param dst_mac: destination mac as string. Example "aa:aa:aa:aa:aa:aa"
        :param src_mac: source mac as string. Example "bb:bb:bb:bb:bb:bb"
        :param kwargs: Extra params per scapy usage.
        :return: None
        """
        self.l2 = inet.Ether(dst=dst_mac, src=src_mac, **kwargs)

    def build_l3_header_ip4(self, src_ip='192.168.0.2', dst_ip='192.168.0.3',
                            protocol='UDP', **kwargs):
        """
        Build a scapy IPV4 L3 object
        :param src_ip: source IP as string in dot notaion format
        :param dst_ip: destination IP as string in dot notation format
        :param protocol: protocol for l4
        :param kwargs: Extra params per scapy usage
        :return: None
        """
        self.l3 = inet.IP(src=src_ip, dst=dst_ip, proto=protocol.lower(),
                          **kwargs)

    def build_vlan_header(self, vlan_id=1, **kwargs):
        """
        Build a Dot1Q scapy object.
        :param vlan_id: The VLAN ID
        :param kwargs: Extra params per scapy usage
        :return: None
        """
        self.vlan = inet.Dot1Q(vlan=vlan_id, **kwargs)

    def create_packet_header(self):
        """
        Create the scapy packet header based on what has been built in this
        instance using the build methods.
        :return: Scapy packet header
        """
        packet = inet.Ether()
        if self.l2:
            packet = self.l2
        if self.vlan:
            packet /= self.vlan
        if self.l3:
            packet /= self.l3
        return packet

    def read_config(self):
        """
        Read the config from the open JSON file.
        :return: Boolean if success, False if failure.
        """
        try:
            self.chassisIP = self.file_data['ChassisManager']['ChassisList'][
                0]['HostName']
            self.chassisPwd = self.file_data['ChassisManager'][
                'ChassisList'][0]['Password']
            self.custom_packet_sizes = self.file_data['TestOptions'][
                'PacketSizes']['CustomPacketSizes']
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
        """
        Read the file as specified in the instance xml_path attribute.
        :return: Boolean if success, False if failure.
        """
        try:
            with open(self.xml_path, 'r', encoding='utf-8') as data_file:
                self.file_data = json.loads(data_file.read())
                return True
        except Exception as e:
            _logger.exception('Exception during Xena xml read: {}'.format(e))
            return False

    def write_config(self):
        """
        Write the config in preparation for exporting the data to a JSON file.
        :return: None
        """
        self.file_data['ChassisManager']['ChassisList'][0][
            'HostName'] = self.chassisIP
        self.file_data['ChassisManager']['ChassisList'][0][
            'Password'] = self.chassisPwd
        self.file_data['TestOptions']['PacketSizes'][
            'CustomPacketSizes'] = self.custom_packet_sizes
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
            'StreamConfig']['HeaderSegments'] = self.segment1
        self.file_data['StreamProfileHandler']['EntityList'][1][
            'StreamConfig']['HeaderSegments'] = self.segment2

    def write_file(self, output_path):
        """
        Write the file as specified in the output_path param
        :param output_path: path to write out in string format
        :return: Boolean if success, False if failure.
        """
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
    x.build_l2_header(dst_mac='ff:ff:ff:ff:ff:ff', src_mac='ee:ee:ee:ee:ee:ee')
    x.build_l3_header_ip4(src_ip='192.168.100.2', dst_ip='192.168.100.3',
                          protocol='udp')
    x.trials = 2
    x.duration = 15
    x.loss_rate = 0
    x.custom_packet_sizes = [64]
    x.add_header_segments()
    x.write_config()
    x.write_file('./testthis.x2544')
    x = XMLConfig('./testthis.x2544')
    for i in decode_byte_array(x.file_data['StreamProfileHandler'][
                                   'EntityList'][0]['StreamConfig'][
                                   'HeaderSegments'][0]['SegmentValue']):
        print(i)
    for i in decode_byte_array(x.file_data['StreamProfileHandler'][
                                   'EntityList'][0]['StreamConfig'][
                                   'HeaderSegments'][1]['SegmentValue']):
        print(i)
    print("src and dst swapped")
    for i in decode_byte_array(x.file_data['StreamProfileHandler'][
                                   'EntityList'][1]['StreamConfig'][
                                   'HeaderSegments'][0]['SegmentValue']):
        print(i)
    for i in decode_byte_array(x.file_data['StreamProfileHandler'][
                                   'EntityList'][1]['StreamConfig'][
                                   'HeaderSegments'][1]['SegmentValue']):
        print(i)
