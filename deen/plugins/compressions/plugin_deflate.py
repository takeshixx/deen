import sys
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
        zlib_encode = zlib.compressobj(-1, zlib.DEFLATED, -15)
        if sys.version_info.major < 3:
            data = buffer(data)
        try:
            zlib_encode.compress(data)
            data = zlib_encode.flush()
        except zlib.error as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginDeflate, self).unprocess(data)
        if sys.version_info.major < 3:
            data = buffer(data)
        try:
            data = zlib.decompress(data, -15)
        except zlib.error as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
