import hashlib

from .. import DeenPlugin


class DeenPluginMysql(DeenPlugin):
    name = 'mysql'
    display_name = 'MySQL'

    def __init__(self):
        super(DeenPluginMysql, self).__init__()

    def process(self, data):
        super(DeenPluginMysql, self).process(data)
        h1 = hashlib.new('sha1')
        h2 = hashlib.new('sha1')
        try:
            h1.update(data)
            h2.update(h1.digest())
            data = h2.hexdigest().encode()
        except Exception as e:
            self.error = e
        return data