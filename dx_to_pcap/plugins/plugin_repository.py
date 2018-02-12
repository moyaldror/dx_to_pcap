from __future__ import absolute_import

from dx_to_pcap.plugins.old_dx_format_plugin import OldDxFormatPlugin
from dx_to_pcap.plugins.new_dx_format_plugin import NewDxFormatPlugin


class PluginsRepository(object):

    _PLUGIN_CLASSES = [OldDxFormatPlugin, NewDxFormatPlugin]

    def __init__(self):
        self._plugin_names_to_classes = {
            plugin_class.__name__: plugin_class for plugin_class in self._PLUGIN_CLASSES
        }

    def get_available_plugins(self):
        return set(plugin.__doc__ for plugin in self._PLUGIN_CLASSES)


