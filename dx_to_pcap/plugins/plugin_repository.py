from __future__ import absolute_import

from dx_to_pcap.plugins.plugin_base import BasePlugin
from dx_to_pcap.plugins.new_dx_format_plugin import NewDxFormatPlugin
from dx_to_pcap.plugins.old_dx_format_plugin import OldDxFormatPlugin
from dx_to_pcap.plugins.high_speed_capture_plugin import HighSpeedCapturePlugin

class PluginRepository(object):
    def __init__(self):
        self.__plugins = [NewDxFormatPlugin(), OldDxFormatPlugin(), HighSpeedCapturePlugin()]

    @property
    def plugins(self):
        return self.__plugins

    def get_available_plugins(self):
        return [plugin.get_plugin_name() for plugin in self.__plugins]

    def get_plugin(self, plugin_name):
        for plugin in self.__plugins:
            if plugin.get_plugin_name() == plugin_name:
                return plugin

        raise Exception('No such plugin!!!')
