import quopri

from .. import DeenPlugin


class DeenPluginQuopri(DeenPlugin):
    name = 'quopri'
    display_name = 'Quopri'
    cmd_name = 'quopri'
    cmd_help='Quopri (RFC 1521) encode/decode data'

    def __init__(self):
        super(DeenPluginQuopri, self).__init__()

    def process(self, data):
        super(DeenPluginQuopri, self).process(data)
        try:
            data = quopri.encodestring(data)
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginQuopri, self).unprocess(data)
        try:
            data = quopri.decodestring(data)
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
