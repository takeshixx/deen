import json

try:
    import dicttoxml
except ImportError:
    DICTTOXML = False
else:
    DICTTOXML = True

from .. import DeenPlugin


class DeenPluginJsonToXmlFormatter(DeenPlugin):
    name = 'jsontoxml_formatter'
    display_name = 'JSON to XML (f)'
    aliases = ['j2x',
               'json2xml']
    cmd_name = 'jsontoxml'
    cmd_help = 'Convert JSON object to XML'

    def __init__(self):
        super(DeenPluginJsonToXmlFormatter, self).__init__()

    @staticmethod
    def prerequisites():
        try:
            import dicttoxml
        except ImportError:
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginJsonToXmlFormatter, self).process(data)
        if not DICTTOXML:
            return
        try:
            data = json.loads(data.decode())
        except (json.JSONDecodeError, TypeError,
                UnicodeDecodeError, AssertionError) as e:
            self.error = e
            return
        try:
            data = dicttoxml.dicttoxml(data)
        except Exception as e:
            self.error = e
        return data