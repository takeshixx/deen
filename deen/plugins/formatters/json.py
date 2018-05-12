import json
import pprint

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
        except (json.JSONDecodeError, TypeError) as e:
            self.error = e
            return
        data = pprint.pformat(data).encode()
        return data