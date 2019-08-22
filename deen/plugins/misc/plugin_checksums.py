import zlib
import codecs

from .. import DeenPlugin

__all__ = ['DeenPluginCrc32',
           'DeenPluginAdler32']


class DeenPluginCrc32(DeenPlugin):
    name = 'crc32'
    display_name = 'CRC32'
    cmd_name = 'crc32'
    cmd_help = 'Calculate CRC32 checksum of data'

    def __init__(self):
        super(DeenPluginCrc32, self).__init__()

    def process(self, data):
        super(DeenPluginCrc32, self).process(data)
        try:
            data = zlib.crc32(data)
            data = hex(data).encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data


class DeenPluginAdler32(DeenPlugin):
    name = 'adler32'
    display_name = 'Adler-32'
    cmd_name = 'adler32'
    cmd_help = 'Calculate Adler-32 checksum of data'

    def __init__(self):
        super(DeenPluginAdler32, self).__init__()

    def process(self, data):
        super(DeenPluginAdler32, self).process(data)
        try:
            data = zlib.adler32(data)
            data = hex(data).encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
