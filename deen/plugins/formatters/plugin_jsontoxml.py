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

    def prerequisites(self):
        try:
            import dicttoxml
        except ImportError:
            self.log_missing_depdendencies('dicttoxml')
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
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        try:
            data = dicttoxml.dicttoxml(data)
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
