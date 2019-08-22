import sys
try:
    import lzma
except ImportError:
    lzma = None

from .. import DeenPlugin


class DeenPluginLzma(DeenPlugin):
    name = 'lzma'
    display_name = 'LZMA'
    cmd_name = 'lzma'
    cmd_help='LZMA compress/decompress data'

    def __init__(self):
        super(DeenPluginLzma, self).__init__()

    def prerequisites(self):
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 3):
            self.log_incompatible_version('3.3')
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginLzma, self).process(data)
        if not lzma:
            self.log.error('lzma module not found')
            return data
        try:
            data = lzma.compress(data)
        except lzma.LZMAError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginLzma, self).unprocess(data)
        if not lzma:
            self.log.error('lzma module not found')
            return data
        results = []
        while True:
            decomp = lzma.LZMADecompressor(lzma.FORMAT_AUTO, None, None)
            try:
                res = decomp.decompress(data)
            except lzma.LZMAError as e:
                self.log.error(e)
                self.log.debug(e, exc_info=True)
                if results:
                    break
                else:
                    self.error = e
                    return
            results.append(res)
            data = decomp.unused_data
            if not data:
                break
            if not decomp.eof:
                ex = lzma.LZMAError('Compressed data ended before the end-of-stream marker was reached')
                self.error = ex
                self.log.error(self.error)
                self.log.debug(self.error, exc_info=True)
        data = b''.join(results)
        return data
