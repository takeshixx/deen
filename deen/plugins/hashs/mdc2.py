import hashlib

from .. import DeenPlugin


class DeenPluginMdc2(DeenPlugin):
    name = 'mdc2'
    display_name = 'MDC-2'

    def __init__(self):
        super(DeenPluginMdc2, self).__init__()

    def process(self, data):
        super(DeenPluginMdc2, self).process(data)
        try:
            h = hashlib.new('mdc2')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
        return data