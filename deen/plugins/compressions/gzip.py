import zlib
import codecs

from .. import DeenPlugin


class DeenPluginGzip(DeenPlugin):
    name = 'gzip'
    display_name = 'gzip'

    def __init__(self):
        super(DeenPluginGzip, self).__init__()

    def process(self, data):
        super(DeenPluginGzip, self).process(data)
        try:
            data = codecs.encode(data, 'zlib')
        except TypeError:
            # Python 2 does not like bytearrays
            data = codecs.encode(buffer(data), 'zlib')
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginGzip, self).unprocess(data)
        try:
            data = zlib.decompress(data, zlib.MAX_WBITS | 32)
        except zlib.error as e:
            self.error = e
        except TypeError:
            try:
                # Python 2 does not like bytearrays
                data = zlib.decompress(buffer(data), zlib.MAX_WBITS | 32)
            except zlib.error as e:
                self.error = e
        return data