import zlib

from .. import DeenPlugin


class DeenPluginGzip(DeenPlugin):
    name = 'gzip'
    display_name = 'gzip'
    cmd_name = 'gzip'
    cmd_help='gzip compress/decompress data'

    def __init__(self):
        super(DeenPluginGzip, self).__init__()

    def process(self, data):
        super(DeenPluginGzip, self).process(data)
        try:
            data = zlib.compress(data)
        except TypeError:
            # Python 2 does not like bytearrays
            data = zlib.compress(buffer(data))
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginGzip, self).unprocess(data)
        try:
            data = zlib.decompress(data, zlib.MAX_WBITS | 32)
        except zlib.error as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        except TypeError:
            try:
                # Python 2 does not like bytearrays
                data = zlib.decompress(buffer(data), zlib.MAX_WBITS | 32)
            except zlib.error as e:
                self.error = e
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
        return data
