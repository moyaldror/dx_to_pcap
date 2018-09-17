from __future__ import absolute_import

from dx_to_pcap.plugins.plugin_base import BasePlugin


class HighSpeedCapturePlugin(BasePlugin):
    '''High speed capture module'''

    START = 'CAPTURE@sp_driver'
    END = ''

    def __init__(self):
        pass

    def get_plugin_name(self):
        return 'HigSpeedCapture'

    def packet_start(self, line):
        return self.START in line

    def packet_end(self, line):
        return line == self.END

    def get_hex_from_line(self, line):
        return line.strip()

    def get_ascii_from_line(self, line):
        return ''

    def get_offset(self):
        return 0
