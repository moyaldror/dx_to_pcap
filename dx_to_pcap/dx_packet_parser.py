from __future__ import absolute_import

from dx_to_pcap.plugins.plugin_base import BasePlugin
from dx_to_pcap.plugins.plugin_repository import PluginRepository
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
    __PLUGIN_REPO = PluginRepository()

    def __init__(self, dx_plugin = ''):
        self._data = []
        self._plugin = dx_plugin if dx_plugin else self.__PLUGIN_REPO.plugins[0].get_plugin_name()
        self._should_add_line = False

    def _get_plugin(self):
        return self.__PLUGIN_REPO.get_plugin(plugin_name=self._plugin)

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
        if ascii_data_to_store:
            while True:
                if len(ascii_data_to_store) >= 16:
                    res.append('{:04x} {} {}\n'.format(
                                index,
                                ' '.join('{}{}'.format(a, b) for a, b in zip(hex_data_to_store[:32:2],
                                                                             hex_data_to_store[1:32:2])),
                                ascii_data_to_store[:16]))
                    hex_data_to_store = hex_data_to_store[32::]
                    ascii_data_to_store = ascii_data_to_store[16::]
                else:
                    res.append('{:04x} {} {}{}\n'.format(
                                index,
                                ' '.join('{}{}'.format(a, b) for a, b in zip(hex_data_to_store[::2], hex_data_to_store[1::2])),
                                                        '   ' * (16 - len(ascii_data_to_store)),
                                ascii_data_to_store[:]))
                    break
                index += 16
        else:
            while True:
                if len(hex_data_to_store) >= 32:
                    res.append('{:04x} {}\n'.format(
                                index,
                                ' '.join('{}{}'.format(a, b) for a, b in zip(hex_data_to_store[:32:2], hex_data_to_store[1:32:2]))));
                    hex_data_to_store = hex_data_to_store[32::]
                else:
                    res.append('{:04x} {}\n'.format(
                                index,
                                ' '.join('{}{}'.format(a, b) for a, b in zip(hex_data_to_store[::2], hex_data_to_store[1::2]))));
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
          raise Exception('Failed to parse packet')

        return pkt

    def consume_line(self, line):
        try:
            res = None

            if self._should_add_line:
                self._data.append(line)

            if self._get_plugin().packet_start(line):
                self._should_add_line = True
            elif self._should_add_line and self._get_plugin().packet_end(line):
                self._should_add_line = False
                self._data.pop()
                res = self._export_packet()
                self._data.clear()

            return res
        except IndexError:
            print('Parsing of the AX log failed. Probably unknown hex dump format. Quitting...')
            sys.exit(1)
