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


class XMLConfig(object):
    def __init__(self, xmlpath):
        self._xmlpath = xmlpath
        self._filedata = dict()
        self._trials = None
        self._duration = None
        self._lossrate = None

        self.read_file()
        self.read_config()

    def read_config(self):
        try:
            self._trials = self._filedata['TestOptions']['TestTypeOptionMap'][
                'Throughput']['Iterations']
            self._duration = self._filedata['TestOptions']['TestTypeOptionMap'][
                'Throughput']['Duration']
            self._lossrate = self._filedata['TestOptions']['TestTypeOptionMap'][
                'Throughput']['RateIterationOptions']['AcceptableLoss']
            return True
        except Exception as e:
            _logger.exception(
                'Error in XML file, setting not found: {}'.format(e))
            return False

    def read_file(self):
        try:
            with open(self._xmlpath, 'r', encoding='utf-8') as data_file:
                self._filedata = json.loads(data_file.read())
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
        self._filedata['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Duration'] = numint

    @property
    def lossrate(self):
        return self._lossrate

    @lossrate.setter
    def lossrate(self, numfloat):
        self._lossrate = numfloat
        self._filedata['TestOptions']['TestTypeOptionMap']['Throughput'][
            'RateIterationOptions']['AcceptableLoss'] = numfloat

    @property
    def trials(self):
        return self._trials

    @trials.setter
    def trials(self, numint):
        self._trials = numint
        self._filedata['TestOptions']['TestTypeOptionMap']['Throughput'][
            'Iterations'] = numint
