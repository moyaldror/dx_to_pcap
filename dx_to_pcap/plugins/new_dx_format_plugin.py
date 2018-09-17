from __future__ import absolute_import

from dx_to_pcap.plugins.plugin_base import BasePlugin


class NewDxFormatPlugin(BasePlugin):
    '''New Dx Format Parser'''

    PREV = 'ENGINE@sp_driver'
    START = '------------------------'
    END = '| seq ='

    def __init__(self):
        self._prev_line = ''

    def get_plugin_name(self):
        return 'NewDxFormat'

    def packet_start(self, line):
        res = False
        if self.START in line and self.PREV in self._prev_line:
            res = True

        self._prev_line = line
        return res

    def packet_end(self, line):
        res = False
        if self.END in line:
            res = True

        self._prev_line = line
        return res

    def get_hex_from_line(self, line):
        return ''.join(''.join(line.strip().split('    ')[1:2]).split('   ')[:2]).replace(' ', '').strip()

    def get_ascii_from_line(self, line):
        return line.strip().split('   ')[len(line.split('   ')) - 1].strip()

    def get_offset(self):
        return 0
