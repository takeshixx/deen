import json

try:
    import xmltodict
except ImportError:
    XMLTODICT = False
else:
    XMLTODICT = True

from .. import DeenPlugin


class DeenPluginXmlToJsonFormatter(DeenPlugin):
    name = 'xmltojson_formatter'
    display_name = 'XML to JSON (f)'
    aliases = ['x2j',
               'xml2json']
    cmd_name = 'xmltojson'
    cmd_help = 'Convert XML to JSON object'

    def __init__(self):
        super(DeenPluginXmlToJsonFormatter, self).__init__()

    def prerequisites(self):
        try:
            import xmltodict
        except ImportError:
            self.log_missing_depdendencies('xmltodict')
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginXmlToJsonFormatter, self).process(data)
        if not XMLTODICT:
            return
        try:
            data = xmltodict.parse(data, xml_attribs=False)
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        try:
            data = json.dumps(data).encode()
        except  Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        return data
