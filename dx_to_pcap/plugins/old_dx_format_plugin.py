from __future__ import absolute_import

from dx_to_pcap.plugins.plugin_base import BasePlugin


class OldDxFormatPlugin(BasePlugin):
    '''Old Dx Format Parser'''

    START = '------------------------ length'
    END = '| seq ='

    def __init__(self):
        pass

    def packet_start(self, line):
        return self.START in line

    def packet_end(self, line):
        return self.END in line

    def get_hex_from_line(self, line):
        return ''.join(line.strip().split('   ')[:2]).replace(' ', '').strip()

    def get_ascii_from_line(self, line):
        return line.strip().split('   ')[len(line.split('   ')) - 1].strip()

    def get_offset(self):
        return 8
