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

import json
import logging

_logger = logging.getLogger(__name__)

# Profile assignment as per generic config file
ETHERNET_PROFILE = (1, 2)
ETHERNET_VLAN_PROFILE = (3, 4)
ETHERNET_VLAN_IP_PROFILE = (5, 6)
ETHERNET_IP_PROFILE = (7, 8)

# JSON lookup location mapping
DURATION = ('TestOptions', 'TestTypeOptionMap', 'Throughput', 'Duration')
LOSSRATE = ('TestOptions', 'TestTypeOptionMap', 'Throughput',
            'RateIterationOptions', 'AcceptableLoss')
MODULE1 = ('PortHandler', 'EntityList', 0, 'PortRef', 'ModuleIndex')
MODULE2 = ('PortHandler', 'EntityList', 1, 'PortRef', 'ModuleIndex')
PORT1 = ('PortHandler', 'EntityList', 0, 'PortRef', 'PortIndex')
PORT1UID = ('PortHandler', 'EntityList', 0, 'ItemID')
PORT2 = ('PortHandler', 'EntityList', 1, 'PortRef', 'PortIndex')
PORT2UID = ('PortHandler', 'EntityList', 1, 'ItemID')
TRIALS = ('TestOptions', 'TestTypeOptionMap', 'Throughput', 'Iterations')


class XMLConfig(object):
    def __init__(self, xmlpath):
        self._xmlpath = xmlpath
        self._filedata = dict()

        # Test config info
        self._trials = None
        self._duration = None
        self._lossrate = None

        # Physical Xena info
        self._module1 = None
        self._module2 = None
        self._port1 = None
        self._port2 = None
        self._port1UID = None
        self._port2UID = None
        self._chassisID = None

        # Read the xml file and configuration settings
        self.read_file()
        self.read_config()

    def read_config(self):
        try:
            self._duration = self._filedata.lookup(*DURATION)
            self._lossrate = self._filedata.lookup(*LOSSRATE)
            self._module1 = self._filedata.lookup(*MODULE1)
            self._module2 = self._filedata.lookup(*MODULE2)
            self._port1 = self._filedata.lookup(*PORT1)
            self._port1UID = self._filedata.lookup(*PORT1UID)
            self._port2 = self._filedata.lookup(*PORT2)
            self._port2UID = self._filedata.lookup(*PORT2UID)
            self._trials = self._filedata.lookup(*TRIALS)
            return True
        except Exception as e:
            _logger.exception(
                'Error in XML file, setting not found: {}'.format(e))
            return False

    def read_file(self):
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
    def duration(self):
        return self._duration

    @duration.setter
    def duration(self, numint):
        self._duration = numint
        set_path(self._filedata, DURATION, numint)

    @property
    def lossrate(self):
        return self._lossrate

    @lossrate.setter
    def lossrate(self, numfloat):
        self._lossrate = numfloat
        set_path(self._filedata, LOSSRATE, numfloat)

    @property
    def port1(self):
        return self._port1

    @port1.setter
    def port1(self, port):
        self._port1 = port
        set_path(self._filedata, PORT1, port)

    @property
    def port1UID(self):
        return self._port1UID

    @property
    def port2(self):
        return self._port2

    @port2.setter
    def port2(self, port):
        self._port2 = port
        set_path(self._filedata, PORT2, port)

    @property
    def port2UID(self):
        return self._port2UID

    @property
    def trials(self):
        return self._trials

    @trials.setter
    def trials(self, numint):
        self._trials = numint
        set_path(self._filedata, TRIALS, numint)


class MyDict(dict):
    def lookup(self, *args):
        tmp = self
        for _ in args:
            tmp = tmp[_]
        return tmp


def set_path(somedict, path, value):
    for x in path[::-1]:
        value = {x: value}
    return deep_update(somedict, value)


def deep_update(original, update):
    for key, value in original.items():
        if key not in update:
            update[key] = value
        elif isinstance(value, dict):
            deep_update(value, update[key])
    return update

if __name__ == "__main__":
    x = XMLConfig(
        "/home/ctrautma/PycharmProjects/Xena-VSPerf/CTTestConfig.x2544")
    x.trials = 3
    print(x._filedata['PortHandler']['EntityList'][0]['PortRef']['ModuleIndex'])
