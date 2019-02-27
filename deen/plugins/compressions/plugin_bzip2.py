import codecs

from .. import DeenPlugin


class DeenPluginBzip2(DeenPlugin):
    name = 'bzip2'
    display_name = 'bzip2'
    cmd_name = 'bzip2'
    cmd_help='bzip2 compress/decompress data'

    def __init__(self):
        super(DeenPluginBzip2, self).__init__()

    def process(self, data):
        super(DeenPluginBzip2, self).process(data)
        try:
            data = codecs.encode(data, 'bz2')
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginBzip2, self).unprocess(data)
        try:
            data = codecs.decode(data, 'bz2')
        except (OSError, IOError) as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
