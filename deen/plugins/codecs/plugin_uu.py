import codecs

from .. import DeenPlugin


class DeenPluginUuencode(DeenPlugin):
    name = 'uuencode'
    display_name = 'Uuencode'
    aliases = ['uu']
    cmd_name = 'uuencode'
    cmd_help='Uuencode encode/decode data'

    def __init__(self):
        super(DeenPluginUuencode, self).__init__()

    def process(self, data):
        super(DeenPluginUuencode, self).process(data)
        try:
            data = codecs.encode(data, 'uu')
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginUuencode, self).unprocess(data)
        try:
            data = codecs.decode(data, 'uu')
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
