import zlib

from .. import DeenPlugin


class DeenPluginDeflate(DeenPlugin):
    name = 'deflate'
    display_name = 'deflate'
    cmd_name = 'deflate'
    cmd_help='Deflate compress/decompress data'

    def __init__(self):
        super(DeenPluginDeflate, self).__init__()

    def process(self, data):
        super(DeenPluginDeflate, self).process(data)
        try:
            data = zlib.compress(data, 'zlib')
        except TypeError:
            # Python 2 does not like bytearrays
            data = zlib.compress(buffer(data), 'zlib')
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginDeflate, self).unprocess(data)
        try:
            data = zlib.decompress(data, -15)
        except zlib.error as e:
            self.error = e
        except TypeError:
            try:
                # Python 2 does not like bytearrays
                data = zlib.decompress(buffer(data), -15)
            except zlib.error as e:
                self.error = e
        return data