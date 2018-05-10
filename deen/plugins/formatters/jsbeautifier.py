import logging

try:
    import jsbeautifier
except ImportError:
    JSBEAUTIFIER = False
else:
    JSBEAUTIFIER = True

from .. import DeenPlugin

LOGGER = logging.getLogger(__name__)


class DeenPluginJsBeautifierFormatter(DeenPlugin):
    name = 'jsbeautifier_formatter'
    display_name = 'JS Beautifier'

    def __init__(self):
        super(DeenPluginJsBeautifierFormatter, self).__init__()

    @staticmethod
    def prerequisites():
        try:
            import jsbeautifier
        except ImportError:
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginJsBeautifierFormatter, self).process(data)
        if not JSBEAUTIFIER:
            LOGGER.warning('jsbeautifier is not available')
            return
        opts = jsbeautifier.default_options()
        opts.unescape_strings = True
        try:
            data = jsbeautifier.beautify(data.decode(), opts).encode()
        except (UnicodeDecodeError, TypeError) as e:
            self.error = e
            return
        return data