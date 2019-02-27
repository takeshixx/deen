from __future__ import absolute_import
from xml.parsers.expat import ExpatError

try:
    # Python 3
    import xml.dom.minidom as minidom
except ImportError:
    # Python 2
    from xml.dom import minidom

from .. import DeenPlugin


class DeenPluginXmlFormatter(DeenPlugin):
    name = 'xml_formatter'
    display_name = 'XML (f)'
    cmd_name = 'xml-format'
    cmd_help = 'Reformat XML data'

    def __init__(self):
        super(DeenPluginXmlFormatter, self).__init__()

    def process(self, data):
        super(DeenPluginXmlFormatter, self).process(data)
        try:
            parser = minidom.parseString(data)
            data = parser.toprettyxml(indent=' ' * 4,
                                      encoding='utf8')
        except ExpatError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
