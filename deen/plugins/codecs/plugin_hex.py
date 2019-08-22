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
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginHex, self).unprocess(data)
        # Remove whitespaces from
        # input data to make decoding
        # of hexdumps easier.
        temp = data.split()
        data = bytearray()
        for t in temp:
            data.extend(t)
        try:
            data = codecs.decode(data, 'hex')
        except (binascii.Error, TypeError) as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
