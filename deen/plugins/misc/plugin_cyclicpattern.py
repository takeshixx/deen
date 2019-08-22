from string import ascii_uppercase, ascii_lowercase, digits

from .. import DeenPlugin

__all__ = ['DeenPluginCyclicPatternCreate',
           'DeenPluginCyclicPatternFind']

MAX_PATTERN_LENGTH = 20280


class DeenPluginCyclicPatternCreate(DeenPlugin):
    name = 'patterncreate'
    display_name = 'Pattern Create'
    cmd_name = 'patternCreate'
    aliases = ['pattern_create',
               'pattern-create',
               'patterncreate']
    cmd_help = 'Create a cyclic pattern for exploit development'

    def __init__(self):
        super(DeenPluginCyclicPatternCreate, self).__init__()

    def process(self, data):
        """Generate a cyclic pattern of a given length up to a
        maximum of MAX_PATTERN_LENGTH - after this the pattern
        would repeat."""
        super(DeenPluginCyclicPatternCreate, self).process(data)
        pattern = ''
        try:
            data = int(data)
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return b'Invalid must be an integer'
        if data > MAX_PATTERN_LENGTH:
            return b'Pattern exceeds maximum length'
        for upper in ascii_uppercase:
            for lower in ascii_lowercase:
                for digit in digits:
                    if len(pattern) < data:
                        pattern += upper + lower + digit
                    else:
                        out = pattern[:data]
                        return out.encode()
        return pattern.encode()


class DeenPluginCyclicPatternFind(DeenPlugin):
    name = 'patternfind'
    display_name = 'Pattern Find'
    cmd_name = 'patternFind'
    aliases = ['pattern_find',
               'pattern-find',
               'patternfind']
    cmd_help = 'Find position of input data in cyclic pattern'

    def __init__(self):
        super(DeenPluginCyclicPatternFind, self).__init__()

    def process(self, data):
        """Search for data in cyclic pattern. Convert from hex
        if needed."""
        super(DeenPluginCyclicPatternFind, self).process(data)
        try:
            needle = data.decode("utf-8")
        except UnicodeDecodeError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return
        try:
            if needle.startswith('0x'):
                # Strip off '0x', convert to ASCII and reverse
                needle = bytes.fromhex(needle[2:])
                needle = needle[::-1].decode("utf-8")
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return ('Unable to convert hex input:{}'.format(e)).encode()
        try:
            haystack = ''
            for upper in ascii_uppercase:
                for lower in ascii_lowercase:
                    for digit in digits:
                        haystack += upper+lower+digit
                        found_at = haystack.find(needle)
                        if found_at > -1:
                            return 'Pattern offset: {}'.format(found_at).encode()
        except TypeError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
            return b'Invalid input data'
        return 'Couldn\'t find {} ({}) anywhere in the pattern.'.format(data, needle).encode()
