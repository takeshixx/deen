from __future__ import absolute_import

try:
    # Python 3
    import html
    html_encode = html.escape
    html_decode = html.unescape
except (ImportError, AttributeError):
    # Python 2
    import cgi
    html_encode = cgi.escape
    from HTMLParser import HTMLParser
    html = HTMLParser()
    html_decode = html.unescape

from .. import DeenPlugin


class DeenPluginHtml(DeenPlugin):
    name = 'html'
    display_name = 'HTML'
    cmd_name = 'html'
    cmd_help='HTML encode/decode data'

    def __init__(self):
        super(DeenPluginHtml, self).__init__()

    def process(self, data):
        super(DeenPluginHtml, self).process(data)
        try:
            # html module requires str?
            data = html_encode(data.decode())
            data = data.encode()
        except Exception as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data

    def unprocess(self, data):
        super(DeenPluginHtml, self).unprocess(data)
        try:
            data = html_decode(data.decode())
            data = data.encode()
        except (UnicodeDecodeError, TypeError) as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data
