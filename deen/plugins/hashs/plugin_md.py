import hashlib

from .. import DeenPlugin

__all__ = ['DeenPluginMd4',
           'DeenPluginMd5']


class DeenPluginMd4(DeenPlugin):
    name = 'md4'
    display_name = 'MD4'
    cmd_name = 'md4'
    cmd_help = 'Hash data with MD4'

    def __init__(self):
        super(DeenPluginMd4, self).__init__()

    def process(self, data):
        super(DeenPluginMd4, self).process(data)
        try:
            h = hashlib.new('md4')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data


class DeenPluginMd5(DeenPlugin):
    name = 'md5'
    display_name = 'MD5'
    cmd_name = 'md5'
    cmd_help = 'Hash data with MD5'

    def __init__(self):
        super(DeenPluginMd5, self).__init__()

    def process(self, data):
        super(DeenPluginMd5, self).process(data)
        try:
            h = hashlib.new('md5')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data