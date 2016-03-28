from tools.pkt_gen.xena.xena import Xena
from tools.pkt_gen.trafficgen.trafficgenhelper import TRAFFIC_DEFAULTS

import inspect
import sys


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


if __name__ == "__main__":
    print("Running Xena VSPerf script UnitTest")

    def go_menu():
        """
        Run the Unittest method menu
        :return: None
        """
        XENA_OBJ = Xena(debug=True)
        from conf import settings
        settings.load_from_dir('./conf')

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