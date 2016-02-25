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
import binascii
import json
import logging
import socket
import struct

_logger = logging.getLogger(__name__)

# Profile assignment as per generic config file
ETHERNET_PROFILE = './profiles/Ethernet.x2544'
ETHERNET_VLAN_PROFILE = './profiles/Ethernet_VLAN.x2544'
ETHERNET_VLAN_IP_PROFILE = './profiles/Ethernet_VLAN_IPV4.x2544'
ETHERNET_IP_PROFILE = './profiles/Ethernet_IPV4.x2544'

# protocol numbers
PROTOCOL_NUM = {6: 'TCP',
                17: 'UDP',
                255: 'RESERVED'}

# TODO Do the VLAN Profile classes
# TODO Document (docstring) and comment this file


class XMLConfig(object):
    def __init__(self, xmlpath):

        self._xmlpath = xmlpath
        self._xmlDataPath = {
            'Chassis_IP': ('ChassisManager', 'ChassisList', 0, 'HostName'),
            'Chassis_Password': ('ChassisManager', 'ChassisList', 0,
                                 'Password'),
            'Duration': ('TestOptions', 'TestTypeOptionMap', 'Throughput',
                         'Duration'),
            'LossRate': ('TestOptions', 'TestTypeOptionMap', 'Throughput',
                         'RateIterationOptions', 'AcceptableLoss'),
            'Module1': ('PortHandler', 'EntityList', 0, 'PortRef',
                        'ModuleIndex'),
            'Module2': ('PortHandler', 'EntityList', 1, 'PortRef',
                        'ModuleIndex'),
            'Packet_Header': ('StreamProfileHandler', 'EntityList', 0,
                              'StreamConfig', 'HeaderSegments'),
            'Port1': ('PortHandler', 'EntityList', 0, 'PortRef', 'PortIndex'),
            'Port1UID': ('PortHandler', 'EntityList', 0, 'ItemID'),
            'Port2': ('PortHandler', 'EntityList', 1, 'PortRef', 'PortIndex'),
            'Port2UID': ('PortHandler', 'EntityList', 1, 'ItemID'),
            'Trials': ('TestOptions', 'TestTypeOptionMap', 'Throughput',
                       'Iterations')}

        self._filedata = dict()

        # Test config info
        self._trials = None
        self._duration = None
        self._lossrate = None

        # Xena Chassis info
        self._chassisIP = None
        self._chassisPwd = None

        # Physical Xena info
        self._module1 = None
        self._module2 = None
        self._port1 = None
        self._port2 = None
        self._port1UID = None
        self._port2UID = None
        self._chassisID = None

        self._srcIP = None
        self._dstIP = None
        self._l4protocol = None
        self._vLANTag = None
        self._vLANid = None
        self._vLANPriority = None

        # Read the xml file and configuration settings
        self.read_file()
        self.read_config()

    @staticmethod
    def decode_bytearray(encstr):
        """ Decodes the base64-encoded string to a byte array
            :param encstr: The base64-encoded string representing a byte array
            :return: The decoded byte array
        """
        decstring = base64.b64decode(encstr)
        b = bytearray()
        b.extend(decstring)
        return b

    @staticmethod
    def encode_bytearray(bytearr):
        """ Encodes the byte array as a base64-encoded string
        :param bytearr: A bytearray containing the bytes to convert
        :return: A base64 encoded string
        """
        encstring = base64.b64encode(bytes(bytearr))
        return encstring

    def read_config(self):
        try:
            self._chassisIP = self._filedata.lookup(
                *self._xmlDataPath['Chassis_IP'])
            self._chassisPwd = self._filedata.lookup(
                *self._xmlDataPath['Chassis_Password'])
            self._duration = self._filedata.lookup(
                *self._xmlDataPath['Duration'])
            self._lossrate = self._filedata.lookup(
                *self._xmlDataPath['LossRate'])
            self._module1 = self._filedata.lookup(
                *self._xmlDataPath['Module1'])
            self._module2 = self._filedata.lookup(
                *self._xmlDataPath['Module2'])
            self._port1 = self._filedata.lookup(
                *self._xmlDataPath['Port1'])
            self._port1UID = self._filedata.lookup(
                *self._xmlDataPath['Port1UID'])
            self._port2 = self._filedata.lookup(
                *self._xmlDataPath['Port2'])
            self._port2UID = self._filedata.lookup(
                *self._xmlDataPath['Port2UID'])
            self._trials = self._filedata.lookup(
                *self._xmlDataPath['Trials'])
            return True
        except Exception as e:
            _logger.exception(
                'Error in XML file, setting not found: {}'.format(e))
            return False

    def read_file(self):
        # RUINED!
        try:
            with open(self._xmlpath, 'r', encoding='utf-8') as data_file:
                self._filedata = MyDict(json.loads(data_file.read()))
                return True
        except Exception as e:
            _logger.exception('Exception during Xena xml read: {}'.format(e))
            return False

    def write_file(self, outputpath):
        try:
            with open(outputpath, 'w',encoding='utf-8') as f:
                json.dump(self._filedata, f, indent=2, sort_keys=True,
                          ensure_ascii=True)
            return True
        except Exception as e:
            _logger.exception('Exception during Xena xml write: {}'.format(e))
            return False

    @property
    def chassis_ip(self):
        return self._chassisIP

    @chassis_ip.setter
    def chassis_ip(self, ip):
        self._chassisIP = ip
        set_path(self._filedata, self._xmlDataPath['Chassis_IP'], ip)

    @property
    def chassis_pwd(self):
        return self._chassisPwd

    @chassis_pwd.setter
    def chassis_pwd(self, pwd):
        self._chassisPwd = pwd
        set_path(self._filedata, self._xmlDataPath['Chassis_Password'], pwd)

    @property
    def duration(self):
        return self._duration

    @duration.setter
    def duration(self, numint):
        self._duration = numint
        set_path(self._filedata, self._xmlDataPath['Duration'], numint)

    @property
    def lossrate(self):
        return self._lossrate

    @lossrate.setter
    def lossrate(self, numfloat):
        self._lossrate = numfloat
        set_path(self._filedata, self._xmlDataPath['LossRate'], numfloat)

    @property
    def port1(self):
        return self._port1

    @port1.setter
    def port1(self, port):
        self._port1 = port
        set_path(self._filedata, self._xmlDataPath['Port1'], port)

    @property
    def port1UID(self):
        return self._port1UID

    @property
    def port2(self):
        return self._port2

    @port2.setter
    def port2(self, port):
        self._port2 = port
        set_path(self._filedata, self._xmlDataPath['Port2'], port)

    @property
    def port2UID(self):
        return self._port2UID

    @property
    def trials(self):
        return self._trials

    @trials.setter
    def trials(self, numint):
        self._trials = numint
        set_path(self._filedata, self._xmlDataPath['Trials'], numint)


class XMLEther(XMLConfig):
    def __init__(self, *args, **kwargs):
        XMLConfig.__init__(self, ETHERNET_PROFILE, *args, **kwargs)

        self._xmlDataPath['EthernetHeader'] = (
            self._xmlDataPath['Packet_Header'] + (0, 'SegmentValue'))

        # packet info
        self._ethernetheader = self.ethernetheader
        self._srcmac = self.srcmac
        self._dstmac = self.dstmac

    @property
    def dstmac(self):
        barray = self.decode_bytearray(self.ethernetheader)
        flatstring = binascii.hexlify(bytes(barray[6:12])).decode('utf-8')
        myiter = iter(flatstring)
        stringwithcolons = ':'.join(a+b for a, b in zip(myiter, myiter))
        return stringwithcolons

    @dstmac.setter
    def dstmac(self, macaddr):
        macaddr = macaddr.split(':')
        barray = self.decode_bytearray(self.ethernetheader)
        for i in range(0, 6):
            barray[i + 6] = int(macaddr[i], 16)
        enc64 = self.encode_bytearray(barray)
        set_path(self._filedata, self._xmlDataPath[
            'EthernetHeader'], enc64.decode('utf-8'))
        self._dstmac = macaddr

    @property
    def ethernetheader(self):
        return self._filedata.lookup(*self._xmlDataPath['EthernetHeader'])

    @property
    def srcmac(self):
        barray = self.decode_bytearray(self.ethernetheader)
        flatstring = binascii.hexlify(bytes(barray[0:6])).decode('utf-8')
        myiter = iter(flatstring)
        stringwithcolons = ':'.join(a+b for a, b in zip(myiter, myiter))
        return stringwithcolons

    @srcmac.setter
    def srcmac(self, macaddr):
        macaddr = macaddr.split(':')
        barray = self.decode_bytearray(self.ethernetheader)
        for i in range(0, 6):
            barray[i] = int(macaddr[i], 16)
        enc64 = self.encode_bytearray(barray)
        set_path(self._filedata, self._xmlDataPath[
            'EthernetHeader'], enc64.decode('utf-8'))
        self._srcmac = macaddr


class XMLEtherIP(XMLEther):
    def __init__(self, *args, **kwargs):
        XMLConfig.__init__(self, ETHERNET_IP_PROFILE, *args, **kwargs)

        self._xmlDataPath['EthernetHeader'] = (
            self._xmlDataPath['Packet_Header'] + (0, 'SegmentValue'))
        self._xmlDataPath['IPHeader'] = (
            self._xmlDataPath['Packet_Header'] + (1, 'SegmentValue'))

        # packet info
        self._ethernetheader = self.ethernetheader
        self._ipheader = self.ipheader
        self._srcmac = self.srcmac
        self._dstmac = self.dstmac
        self._dstIP = self._dstIP
        self._srcIP = self._srcIP
        self._l4proto = self.l4proto

    @property
    def dstIP(self):
        barray = self.decode_bytearray(self.ipheader)
        flatstring = binascii.hexlify(bytes(barray[16:20])).decode('utf-8')
        addr_long = int(flatstring, 16)
        return socket.inet_ntoa(struct.pack("!L", addr_long))

    @dstIP.setter
    def dstIP(self, ipaddr):
        octets = ipaddr.split('.')
        barray = self.decode_bytearray(self.ipheader)
        for i in range(0, 4):
            barray[i + 16] = int(octets[i])
        enc64 = self.encode_bytearray(barray)
        set_path(self._filedata, self._xmlDataPath[
            'IPHeader'], enc64.decode('utf-8'))
        self._dstIP = ipaddr

    @property
    def ipheader(self):
        return self._filedata.lookup(*self._xmlDataPath['IPHeader'])

    @property
    def l4proto(self):
        barray = self.decode_bytearray(self.ipheader)
        value = barray[9]
        if value not in PROTOCOL_NUM.keys():
            _logger.error(
                'Protocol number {} in L3 not found in XenaXML Proto var.')
            return None
        else:
            return PROTOCOL_NUM[barray[9]]

    @l4proto.setter
    def l4proto(self, protocol):
        protocol = protocol.upper()

        # reverse the key values in the PROTOCOL_NUM and get the int value
        res = dict((v, k) for k, v in PROTOCOL_NUM.items())
        value = res[protocol]

        barray = self.decode_bytearray(self.ipheader)
        barray[9] = value
        enc64 = self.encode_bytearray(barray)
        set_path(self._filedata, self._xmlDataPath[
            'IPHeader'], enc64.decode('utf-8'))
        self._l4proto = protocol

    @property
    def srcIP(self):
        barray = self.decode_bytearray(self.ipheader)
        flatstring = binascii.hexlify(bytes(barray[12:16])).decode('utf-8')
        addr_long = int(flatstring, 16)
        return socket.inet_ntoa(struct.pack("!L", addr_long))

    @srcIP.setter
    def srcIP(self, ipaddr):
        octets = ipaddr.split('.')
        barray = self.decode_bytearray(self.ipheader)
        for i in range(0, 4):
            barray[i + 12] = int(octets[i])
        enc64 = self.encode_bytearray(barray)
        set_path(self._filedata, self._xmlDataPath[
            'IPHeader'], enc64.decode('utf-8'))
        self._srcIP = ipaddr


class MyDict(dict):
    def lookup(self, *args):
        tmp = self
        for _ in args:
            tmp = tmp[_]
        return tmp


def set_path(somedict, path, value):
    comstr = "somedict"
    for p in path:
        if type(p) == str:
            comstr = "{}['{}']".format(comstr, p)
        else:
            comstr = "{}[{}]".format(comstr, p)
    if type(value) == str:
        exec("{} = '{}'".format(comstr, value))
    else:
        exec("{} = {}".format(comstr, value))

if __name__ == "__main__":
    print("Running UnitTest for XenaXML")
    x = XMLEtherIP()
    x.trials = 3
    print(x.srcmac, x.dstmac)
    x.srcmac, x.dstmac = ('cc:cc:cc:cc:cc:cc', 'dd:dd:dd:dd:dd:dd')
    print(x.srcmac, x.dstmac)
    print(x.srcIP, x.dstIP)
    x.srcIP, x.dstIP = ('192.168.100.10', '192.168.100.11')
    print(x.srcIP, x.dstIP)
    print(x.l4proto)
    x.l4proto = 'udp'
    print(x.l4proto)
    x.write_file('./profiles/test.x2544')

