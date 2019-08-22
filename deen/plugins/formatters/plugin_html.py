from __future__ import absolute_import
from xml.parsers.expat import ExpatError

try:
    # Python 3
    import xml.dom.minidom as minidom
except ImportError:
    # Python 2
    from xml.dom import minidom

from .. import DeenPlugin


class DeenPluginHtmlFormatter(DeenPlugin):
    name = 'html_formatter'
    display_name = 'HTML (f)'
    cmd_name = 'html-format'
    cmd_help = 'Reformat HTML data'

    def __init__(self):
        super(DeenPluginHtmlFormatter, self).__init__()

    def process(self, data):
        super(DeenPluginHtmlFormatter, self).process(data)
        try:
            parser = minidom.parseString(data)
            document = parser.toprettyxml(indent='  ',
                                          encoding='utf8')
            if document.startswith(b'<?xml version="1.0" encoding="utf8"?>\n') and \
                    not data.startswith(b'<?xml version="1.0" encoding="utf8"?>'):
                index = document.index(b'\n')
                document = document[index + 1:]
            data = document
        except ExpatError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
