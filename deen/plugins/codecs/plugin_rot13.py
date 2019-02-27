import codecs

from .. import DeenPlugin


class DeenPluginRot13(DeenPlugin):
    name = 'rot13'
    display_name = 'Rot13'
    cmd_name = 'rot13'
    cmd_help='Rot13 encode/decode data'

    def __init__(self):
        super(DeenPluginRot13, self).__init__()

    def process(self, data):
        super(DeenPluginRot13, self).process(data)
        try:
            data = codecs.encode(data.decode(), 'rot_13')
            data = data.encode()
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginRot13, self).unprocess(data)
        try:
            data = codecs.decode(data.decode(), 'rot_13')
            data = data.encode()
        except UnicodeDecodeError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
