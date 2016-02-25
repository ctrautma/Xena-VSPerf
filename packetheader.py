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

import binascii
import logging

# scapy imports
# pip install scapy to install on python 2.x
# pip install scapy-python3 for python 3.x
import scapy.layers.inet as inet

_logger = logging.getLogger(__name__)


class PacketHeader(object):
    def __init__(self):
        self.l2 = None
        self.l3 = None
        self.vlan = None

    def build_l2_header(self, srcmac, dstmac):
        self.l2 = inet.Ether(src=srcmac, dst=dstmac)

    def build_l3_header(self, srcip, dstip, protocol):
        self.l3 = inet.IP(src=srcip, dst=dstip, proto=protocol.lower())

    def build_vlan_tag(self, vlantag, priority, ID):
        self.vlan = inet.Dot1Q(vlan=vlantag, prio=priority, id=ID)

    def get_header(self):
        header = (self.l2, self.vlan, self.l3)
        headerprocess = list()
        for h in header:
            if h:
                headerprocess.append(h)
        _logger.debug("Packet header generated from scapy: {}".format(
            headerprocess))
        newheader = headerprocess[0]
        for h in headerprocess[1:]:
            newheader /= h
        packet_bytes = bytes(newheader)
        packet_hex = '0x' + binascii.hexlify(packet_bytes).decode('utf-8')
        return packet_hex

if __name__ == "__main__":
    p = PacketHeader()
    p.build_l2_header('aa:aa:aa:aa:aa:aa', 'bb:bb:bb:bb:bb:bb')
    p.build_l3_header('192.168.190.50', '192.168.190.51', 'UDP')
    p.build_vlan_tag(5, 0, 0)
    header = p.get_header()
    print(header)
