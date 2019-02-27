import logging

try:
    import jsbeautifier
except ImportError:
    JSBEAUTIFIER = False
else:
    JSBEAUTIFIER = True

from .. import DeenPlugin


class DeenPluginJsBeautifierFormatter(DeenPlugin):
    name = 'jsbeautifier_formatter'
    display_name = 'JS Beautifier (f)'
    cmd_name = 'jsbeautifier-format'
    cmd_help = 'Deobfuscate JavaScript code with JS Beautifier'

    def __init__(self):
        super(DeenPluginJsBeautifierFormatter, self).__init__()

    def prerequisites(self):
        try:
            import jsbeautifier
        except ImportError:
            self.log_missing_depdendencies('jsbeautifier')
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginJsBeautifierFormatter, self).process(data)
        if not JSBEAUTIFIER:
            self.log.warning('jsbeautifier is not available')
            return
        opts = jsbeautifier.default_options()
        opts.unescape_strings = True
        try:
            data = jsbeautifier.beautify(data.decode(), opts).encode()
        except (UnicodeDecodeError, TypeError) as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        return data
