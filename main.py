from __future__ import absolute_import

import sys
import os
import signal
sys.stderr = None
from scapy.all import wrpcap
sys.stderr = sys.__stderr__
from dx_to_pcap.arg_parser import DxToPcapArgParser
from dx_to_pcap.dx_packet_parser import DxPacketParser
from collections import OrderedDict
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

in_files = args.dx_files
max_output_size = args.max_pcap_size
use_old_format = args.use_old_dx_format

mp_nums = OrderedDict()
output_file_name = 'mp{}.sp{}.{}.pcap'


def fill_mp_sp_arrays():
    try:
        for dx_file in in_files:
            file_name_arr = dx_file.split('.')
            mp_num = int(file_name_arr[2][2:])
            sp_num = int(file_name_arr[3][2:])
            mp_sps = mp_nums.get(mp_num, [])

            if sp_num not in mp_sps:
                mp_sps.append(sp_num)

            mp_nums[mp_num] = mp_sps
    except:
        print('One or more of the file names are in the wrong convention, Quitting...')
        sys.exit(1)


def create_new_pcap_file(pcap_name):
    with open(pcap_name, 'w'):
        pass


fill_mp_sp_arrays()
for mp in mp_nums.keys():
    for sp in mp_nums[mp]:
        output_file_index = 1
        create_new_pcap_file(pcap_name=output_file_name.format(mp, sp, output_file_index))
        for i in range(50, -1, -1):
            dx_file = 'dx_write.tmp.mp{}.sp{}{}'.format(mp, sp, '.{}'.format(i) if i > 0 else '')
            try:
                with open(dx_file, 'rb') as f:
                    print('Parsing ', dx_file)
                    packet_parser = DxPacketParser(1 if use_old_format else 0)

                    for line in f.readlines():
                        try:
                            line = line.decode('utf8')
                        except UnicodeDecodeError:
                            new_line = []
                            for c in line:
                                try:
                                    c = chr(c)
                                except UnicodeDecodeError:
                                    c = format(c, '02x')
                                new_line.append(c)
                            line = ''.join(new_line)
                        res = packet_parser.consume_line(line.strip())
                        if res is not None:
                            if os.stat(output_file_name.format(mp, sp, output_file_index)).st_size >= max_output_size:
                                output_file_index += 1
                                create_new_pcap_file(pcap_name=output_file_name.format(mp, sp, output_file_index))
                            wrpcap(output_file_name.format(mp, sp, output_file_index), res, append=True)
            except FileNotFoundError:
                pass
