import xml.dom.minidom
from xml.parsers.expat import ExpatError

from .. import DeenPlugin


class DeenPluginHtmlFormatter(DeenPlugin):
    name = 'html_formatter'
    display_name = 'HTML'

    def __init__(self):
        super(DeenPluginHtmlFormatter, self).__init__()

    def process(self, data):
        super(DeenPluginHtmlFormatter, self).process(data)
        try:
            parser = xml.dom.minidom.parseString(data)
            document = parser.toprettyxml(indent='  ',
                                          encoding='utf8')
            if document.startswith(b'<?xml version="1.0" encoding="utf8"?>\n') and \
                    not data.startswith(b'<?xml version="1.0" encoding="utf8"?>'):
                index = document.index(b'\n')
                document = document[index + 1:]
            data = document
        except ExpatError as e:
            self.error = e
        return data