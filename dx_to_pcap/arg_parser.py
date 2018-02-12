from __future__ import absolute_import

import argparse
import sys
from collections import OrderedDict


def non_negative_float(value):
    try:
        float_val = float(value)
        if float_val <= 0:
            raise argparse.ArgumentTypeError('Negative or Zero values are forbidden')

        return float_val
    except Exception as e:
        raise argparse.ArgumentTypeError(str(e))


class DxToPcapArgParser:
    _DxFormatDict = OrderedDict({'OldFormat': 0, 'NewFormat': 1})

    def _get_format_value(self, value):
        return self._DxFormatDict[value]

    _MAX_PCAP_SIZE = 5  # MB

    def __init__(self):
        self.parser = argparse.ArgumentParser(prog='dx_to_pcap',
                                              epilog='Created By: Dror Moyal - Radware AX Group',
                                              description='Convert AX log files to pcap file',
                                              formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        self.parser.add_argument('--version', action='version',
                                 version='%(prog)s {}, Written By: Dror Moyal 2018'
                                 .format('1.0.0'))
        self.parser.add_argument('--dx_files', action='store', dest='dx_files', nargs='+',
                                 help='AX log files to parse. Files must be in the format of dx_write.tmp.<mp>.<sp>' \
                                 'All files must be from the same MP and same SP')
        self.parser.add_argument('--format', default='NewFormat',
                                 action='store', dest='parse_format',
                                 choices=self._DxFormatDict.keys(),
                                 help='The format of the hex dump in the AX log')
        self.parser.add_argument('--max_pcap_size', type=non_negative_float, default=self._MAX_PCAP_SIZE,
                                 action='store', dest='max_pcap_size',
                                 help='Maximum pcap file size (MB). When max size reached a new file will be created')

    def parse_args(self, args=sys.argv[1:]):
        args = self.parser.parse_args(args)
        args.parse_format = self._get_format_value(args.parse_format)
        args.max_pcap_size = args.max_pcap_size * 1024 * 1024
        return args
