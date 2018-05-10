import hashlib

from .. import DeenPlugin

__all__ = ['DeenPluginBlake2b',
           'DeenPluginBlake2s']


class DeenPluginBlake2b(DeenPlugin):
    name = 'blake2b'
    display_name = 'BLAKE2b'

    def __init__(self):
        super(DeenPluginBlake2b, self).__init__()

    def process(self, data):
        super(DeenPluginBlake2b, self).process(data)
        try:
            h = hashlib.new('blake2b')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
        return data


class DeenPluginBlake2s(DeenPlugin):
    name = 'blake2s'
    display_name = 'BLAKE2s'

    def __init__(self):
        super(DeenPluginBlake2s, self).__init__()

    def process(self, data):
        super(DeenPluginBlake2s, self).process(data)
        try:
            h = hashlib.new('blake2s')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
        return data