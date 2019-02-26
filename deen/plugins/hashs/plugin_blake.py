import sys
import hashlib

from .. import DeenPlugin

__all__ = ['DeenPluginBlake2b',
           'DeenPluginBlake2s']


class DeenPluginBlake2b(DeenPlugin):
    name = 'blake2b'
    display_name = 'BLAKE2b'
    cmd_name = 'blake2b'
    cmd_help = 'Hash data with BLAKE2b'

    def __init__(self):
        super(DeenPluginBlake2b, self).__init__()

    def prerequisites(self):
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 6):
            self.log_incompatible_version('3.6')
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginBlake2b, self).process(data)
        try:
            h = hashlib.new('blake2b')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data


class DeenPluginBlake2s(DeenPlugin):
    name = 'blake2s'
    display_name = 'BLAKE2s'
    cmd_name = 'blake2s'
    cmd_help = 'Hash data with BLAKE2s'

    def __init__(self):
        super(DeenPluginBlake2s, self).__init__()

    def prerequisites(self):
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 6):
            self.log_incompatible_version('3.6')
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginBlake2s, self).process(data)
        try:
            h = hashlib.new('blake2s')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data