import codecs
import binascii

from .. import DeenPlugin


class DeenPluginHex(DeenPlugin):
    name = 'hex'
    display_name = 'Hex'
    cmd_name = 'hex'
    cmd_help='Hex encode/decode data'

    def __init__(self):
        super(DeenPluginHex, self).__init__()

    def process(self, data):
        super(DeenPluginHex, self).process(data)
        try:
            data = codecs.encode(data, 'hex')
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginHex, self).unprocess(data)
        try:
            data = codecs.decode(data, 'hex')
        except (binascii.Error, TypeError) as e:
            self.error = e
        return data