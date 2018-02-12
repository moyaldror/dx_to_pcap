from __future__ import absolute_import

from dx_to_pcap.plugins.plugin_base import BasePlugin
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import Ether, import_hexcap
import sys

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO


class DxPacketParser:
    def __init__(self, plugin):
        if not plugin or not isinstance(plugin, BasePlugin):
            raise ValueError('Plugin must be an instance of dx_to_pcap.plugins.plugin_base.BasePlugin')
        self._data = []
        self._plugin = plugin
        self._should_add_line = False

    def _fix_packet(self):
        res = []
        hex_data_to_store = []
        ascii_data_to_store = []

        for line in self._data:
            ascii_data_to_store.append(self._plugin.get_ascii_from_line(line))
            hex_data_to_store.append(self._plugin.get_hex_from_line(line))

        hex_data_to_store = ''.join(hex_data_to_store)[self._plugin.get_offset() * 2:]
        ascii_data_to_store = ''.join(ascii_data_to_store)[self._plugin.get_offset():]

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
        old_stdin, sys.stdin = sys.stdin, StringIO(''.join([*data, chr(4)]))
        pkt = Ether(import_hexcap())
        sys.stdin = old_stdin
        return pkt

    def _export_packet(self):
        data_io = self._fix_packet()
        return self._read_hex(data=data_io)

    def consume_line(self, line):
        try:
            res = None

            if self._should_add_line:
                self._data.append(line)

            if self._plugin.packet_start(line):
                self._should_add_line = True
            elif self._plugin.packet_end(line):
                self._should_add_line = False
                self._data.pop()
                res = self._export_packet()
                self._data.clear()

            return res
        except IndexError:
            print('Parsing of the AX log failed. Probably bad format choosen. Quitting...')
            sys.exit(1)
