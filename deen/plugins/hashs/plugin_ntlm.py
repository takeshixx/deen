import hashlib

from .. import DeenPlugin


class DeenPluginNtlm(DeenPlugin):
    name = 'ntlm'
    display_name = 'NTLM'
    cmd_name = 'ntlm'
    cmd_help = 'Hash password with NTLM'

    def __init__(self):
        super(DeenPluginNtlm, self).__init__()

    def process(self, data):
        super(DeenPluginNtlm, self).process(data)
        h = hashlib.new('md4')
        try:
            data = data.decode()
            h.update(data.encode('utf-16-le'))
            data = h.hexdigest().encode()
        except UnicodeDecodeError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data