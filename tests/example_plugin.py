import sys

from deen.plugins import DeenPlugin


class DeenPluginExample(DeenPlugin):
    name = 'example'
    display_name = 'Example Plugin'
    aliases = ['ex',
               'myexampleplugin']

    def __init__(self):
        super(DeenPluginExample, self).__init__()

    @staticmethod
    def prerequisites():
        if sys.version_info.major < 3 or \
                (sys.version_info.major == 3 and
                         sys.version_info.minor < 4):
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginExample, self).process(data)
        try:
            data = data + b'EXAMPLEPLUGINSTUFF'
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginExample, self).unprocess(data)
        if data.endswith(b'EXAMPLEPLUGINSTUFF'):
            data = data[:-18]
        return data