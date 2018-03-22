from __future__ import absolute_import

from dx_to_pcap.plugins.plugin_base import BasePlugin
from dx_to_pcap.plugins.new_dx_format_plugin import NewDxFormatPlugin
from dx_to_pcap.plugins.old_dx_format_plugin import OldDxFormatPlugin
import logging
import sys
sys.stderr = None
from scapy.all import Ether, import_hexcap, TCP
sys.stderr = sys.__stderr__

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class DxPacketParser:
    _PLUGINS = [NewDxFormatPlugin(), OldDxFormatPlugin()]
    #_PLUGINS = [OldDxFormatPlugin()]

    def __init__(self, _plugin = 0):
        if _plugin == 0:
            self._can_toggle = True
        else:
            self._can_toggle = False
        self._data = []
        self._plugin = _plugin
        self._should_add_line = False

    def _get_plugin(self):
        return self._PLUGINS[self._plugin]

    def _toggle_parser_plugin(self):
        if self._can_toggle:
            self._plugin = (self._plugin + 1) % 2

    def _fix_packet(self):
        res = []
        hex_data_to_store = []
        ascii_data_to_store = []

        for line in self._data:
            ascii_data_to_store.append(self._get_plugin().get_ascii_from_line(line))
            hex_data_to_store.append(self._get_plugin().get_hex_from_line(line))

        hex_data_to_store = ''.join(hex_data_to_store)[self._get_plugin().get_offset() * 2:]
        ascii_data_to_store = ''.join(ascii_data_to_store)[self._get_plugin().get_offset():]

        index = 0
        while True:
            if len(ascii_data_to_store) >= 16:
                res.append('{:04x} {} {}\n'.format(index,
                                                      ' '.join(
                                                          '{}{}'.format(a, b) for a, b in zip(hex_data_to_store[:32:2],
                                                                                              hex_data_to_store[
                                                                                              1:32:2])),
                                                      ascii_data_to_store[:16]))
                hex_data_to_store = hex_data_to_store[32::]
                ascii_data_to_store = ascii_data_to_store[16::]
            else:
                res.append('{:04x} {} {}{}\n'.format(index,
                                                        ' '.join('{}{}'.format(a, b) for a, b in
                                                                 zip(hex_data_to_store[::2], hex_data_to_store[1::2])),
                                                        '   ' * (16 - len(ascii_data_to_store)),
                                                        ascii_data_to_store[:]))
                break
            index += 16
        return res

    @staticmethod
    def _read_hex(data):
        old_stdin, sys.stdin = sys.stdin, StringIO(''.join(data))
        pkt = Ether(import_hexcap())
        sys.stdin = old_stdin
        return pkt

    def _export_packet(self):
        data_io = self._fix_packet()
        data_io.append(chr(4))
        pkt = self._read_hex(data=data_io)
        if pkt.getlayer(TCP) is None:
            self._toggle_parser_plugin()
            pkt = self._read_hex(data=data_io)
            if pkt.getlayer(TCP) is None:
                raise Exception('Failed to parse packet')
        return pkt

    def consume_line(self, line):
        try:
            res = None

            if self._should_add_line:
                self._data.append(line)

            if self._get_plugin().packet_start(line):
                self._should_add_line = True
            elif self._get_plugin().packet_end(line):
                self._should_add_line = False
                self._data.pop()
                res = self._export_packet()
                self._data.clear()

            return res
        except IndexError:
            print('Parsing of the AX log failed. Probably unknown hex dump format. Quitting...')
            sys.exit(1)
