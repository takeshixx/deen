try:
    # Python 3
    import urllib.parse as urllibparse
except ImportError:
    # Python 2
    import urllib as urllibparse

from .. import DeenPlugin


class DeenPluginUrl(DeenPlugin):
    name = 'url'
    display_name = 'URL'

    def __init__(self):
        super(DeenPluginUrl, self).__init__()

    def process(self, data):
        super(DeenPluginUrl, self).process(data)
        try:
            # urllib requires str?
            data = urllibparse.quote_plus(data.decode())
            data = data.encode()
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginUrl, self).unprocess(data)
        try:
            data = urllibparse.unquote_plus(data.decode())
            data = data.encode()
        except (UnicodeDecodeError, TypeError) as e:
            self.error = e
        return data