import sys
import base64
import binascii

from .. import DeenPlugin

__all__ = ['DeenPluginBase64',
           'DeenPluginBase64Url',
           'DeenPluginBase32',
           'DeenPluginBase85']


class DeenPluginBase64(DeenPlugin):
    name = 'base64'
    display_name = 'Base64'
    aliases = ['b64']

    def __init__(self):
        super(DeenPluginBase64, self).__init__()

    def process(self, data):
        super(DeenPluginBase64, self).process(data)
        try:
            data = base64.b64encode(data)
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginBase64, self).unprocess(data)
        # Remove new lines and carriage returns from
        # Base64 encoded data.
        data = data.replace(b'\n', b'').replace(b'\r', b'')
        # If the padding character is missing, restore it.
        padding = len(data) % 4
        if padding != 0:
            data += b'=' * (4 - padding)
        try:
            data = base64.b64decode(data)
        except binascii.Error as e:
            self.error = e
        return data


class DeenPluginBase64Url(DeenPlugin):
    name = 'base64'
    display_name = 'Base64 URL'
    aliases = ['base64-url',
               'base64url',
               'b64-url',
               'b64url']

    def __init__(self):
        super(DeenPluginBase64Url, self).__init__()

    def process(self, data):
        super(DeenPluginBase64Url, self).process(data)
        try:
            data = base64.urlsafe_b64encode(data)
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginBase64Url, self).unprocess(data)
        # Remove new lines and carriage returns from
        # Base64 encoded data.
        data = data.replace(b'\n', b'').replace(b'\r', b'')
        try:
            data = base64.urlsafe_b64decode(data)
        except binascii.Error as e:
            self.error = e
        return data


class DeenPluginBase32(DeenPlugin):
    name = 'base32'
    display_name = 'Base32'
    aliases = ['b32']

    def __init__(self):
        super(DeenPluginBase32, self).__init__()

    def process(self, data):
        super(DeenPluginBase32, self).process(data)
        try:
            data = base64.b32encode(data)
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginBase32, self).unprocess(data)
        # Remove new lines and carriage returns from
        # Base32 encoded data.
        data = data.replace(b'\n', b'').replace(b'\r', b'')
        try:
            data = base64.b32decode(data)
        except binascii.Error as e:
            self.error = e
        return data


class DeenPluginBase85(DeenPlugin):
    name = 'base85'
    display_name = 'Base85'
    aliases = ['b85']

    def __init__(self):
        super(DeenPluginBase85, self).__init__()

    @staticmethod
    def prerequisites():
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 4):
            return False
        else:
            return True

    def process(self, data):
        super(DeenPluginBase85, self).process(data)
        try:
            data = base64.b85encode(data)
        except Exception as e:
            self.error = e
        return data

    def unprocess(self, data):
        super(DeenPluginBase85, self).unprocess(data)
        # Remove new lines and carriage returns from
        # Base85 encoded data.
        data = data.replace(b'\n', b'').replace(b'\r', b'')
        try:
            data = base64.b85decode(data)
        except (binascii.Error, ValueError) as e:
            self.error = e
        return data