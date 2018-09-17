from abc import ABCMeta, abstractmethod


class BasePlugin:
    __metaclass__ = ABCMeta

    @abstractmethod
    def get_plugin_name(self):
        raise NotImplementedError()

    @abstractmethod
    def packet_start(self, line):
        raise NotImplementedError()

    @abstractmethod
    def packet_end(self, line):
        raise NotImplementedError()

    @abstractmethod
    def get_hex_from_line(self, line):
        raise NotImplementedError()

    @abstractmethod
    def get_ascii_from_line(self, line):
        raise NotImplementedError()

    @abstractmethod
    def get_offset(self):
        raise NotImplementedError()
