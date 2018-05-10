import xml.dom.minidom
from xml.parsers.expat import ExpatError

from .. import DeenPlugin


class DeenPluginXmlFormatter(DeenPlugin):
    name = 'xml_formatter'
    display_name = 'XML'

    def __init__(self):
        super(DeenPluginXmlFormatter, self).__init__()

    def process(self, data):
        super(DeenPluginXmlFormatter, self).process(data)
        try:
            parser = xml.dom.minidom.parseString(data)
            data = parser.toprettyxml(indent=' ' * 4,
                                      encoding='utf8')
        except ExpatError as e:
            self.error = e
        return data