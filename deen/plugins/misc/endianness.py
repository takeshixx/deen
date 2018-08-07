from .. import DeenPlugin


class DeenPluginEndianess(DeenPlugin):
    name = 'endianness'
    display_name = 'Swap Endianness'
    aliases = ['endian']
    cmd_name = 'endianness'
    cmd_help='Swap byte order between little- and big-endian.'

    def __init__(self):
        super(DeenPluginEndianess, self).__init__()

    def process(self, data):
        super(DeenPluginEndianess, self).process(data)
        if isinstance(data, bytes):
            data = bytearray(data)
        data.reverse()
        return data
