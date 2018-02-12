from __future__ import absolute_import

import sys
import os
import signal


#import logging
#logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
sys.stderr = None
from scapy.all import wrpcap
sys.stderr = sys.__stderr__
from dx_to_pcap.arg_parser import DxToPcapArgParser
from dx_to_pcap.dx_packet_parser import DxPacketParser
from dx_to_pcap.plugins.new_dx_format_plugin import NewDxFormatPlugin
from dx_to_pcap.plugins.old_dx_format_plugin import OldDxFormatPlugin


try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


def signal_handler(signal, frame):
    print('Caught Ctrl+C! Quitting...')
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)

parser = DxToPcapArgParser()
args = parser.parse_args()

new_format = args.parse_format
in_files = args.dx_files
max_output_size = args.max_pcap_size

if new_format:
    plugin = NewDxFormatPlugin()
else:
    plugin = OldDxFormatPlugin()

mp_num = None
sp_num = None
output_file_name = 'dx_write.{}.pcap'
output_file_index = 1


def validate_files():
    global mp_num
    global sp_num

    try:
        for dx_file in in_files:
            file_name_arr = dx_file.split('.')
            if not mp_num:
                mp_num = int(file_name_arr[2][2:])
                sp_num = int(file_name_arr[3][2:])
            elif mp_num != int(file_name_arr[2][2:]) or sp_num != int(file_name_arr[3][2:]):
                print('Not all files are from the same SP/MP. Quitting...')
                sys.exit(1)
    except:
        print('One or more of the file names are in the wrong convention, Quitting...')
        sys.exit(1)


validate_files()

with open(output_file_name.format(output_file_index), 'w') as f:
    pass

for i in range(50, -1, -1):
    dx_file = 'dx_write.tmp.mp{}.sp{}{}'.format(mp_num, sp_num, '.{}'.format(i) if i > 0 else '')
    try:
        with open(dx_file, 'r') as f:
            print('Parsing ', dx_file)
            packet_parser = DxPacketParser(plugin=plugin)

            for line in f.readlines():
                res = packet_parser.consume_line(line.strip())
                if res is not None:
                    if os.stat(output_file_name.format(output_file_index)).st_size >= max_output_size:
                        output_file_index += 1
                        with open(output_file_name.format(output_file_index), 'w'):
                            pass
                    wrpcap(output_file_name.format(output_file_index), res, append=True)
    except FileNotFoundError:
        pass
