import json

from .. import DeenPlugin


class DeenPluginJsonFormatter(DeenPlugin):
    name = 'json_formatter'
    display_name = 'JSON (f)'
    cmd_name = 'json-format'
    cmd_help = 'Reformat JSON data'

    def __init__(self):
        super(DeenPluginJsonFormatter, self).__init__()

    def process(self, data):
        super(DeenPluginJsonFormatter, self).process(data)
        try:
            data = json.loads(data.decode())
        except (json.JSONDecodeError, TypeError,
                UnicodeDecodeError, AssertionError) as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        data = json.dumps(data, sort_keys=True,
                          indent=4, separators=(',', ': '))
        data = data.encode()
        return data
