import codecs
import binascii

try:
    import ebcdic
except ImportError:
    ebcdic = None

from .. import DeenPlugin


class DeenPluginEbcdic(DeenPlugin):
    name = 'ebcdic'
    display_name = 'EBCDIC'
    cmd_name = 'ebcdic'
    cmd_help='EBCDIC encode/decode data'

    def __init__(self):
        super(DeenPluginEbcdic, self).__init__()

    def process(self, data):
        super(DeenPluginEbcdic, self).process(data)
        try:
            data = data.decode().encode('cp1140')
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginEbcdic, self).unprocess(data)
        temp = data.split()
        data = bytearray()
        for t in temp:
            data.extend(t)
        try:
            data = data.decode('cp1140').encode()
        except (binascii.Error, TypeError) as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
