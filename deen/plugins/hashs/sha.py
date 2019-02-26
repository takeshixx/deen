import hashlib

from .. import DeenPlugin

__all__ = ['DeenPluginSha1',
           'DeenPluginSha224',
           'DeenPluginSha256',
           'DeenPluginSha384',
           'DeenPluginSha512']


class DeenPluginSha1(DeenPlugin):
    name = 'sha1'
    display_name = 'SHA1'
    cmd_name = 'sha1'
    cmd_help = 'Hash data with SHA1'

    def __init__(self):
        super(DeenPluginSha1, self).__init__()

    def process(self, data):
        super(DeenPluginSha1, self).process(data)
        try:
            h = hashlib.new('sha1')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data


class DeenPluginSha224(DeenPlugin):
    name = 'sha224'
    display_name = 'SHA224'
    cmd_name = 'sha224'
    cmd_help = 'Hash data with SHA224'

    def __init__(self):
        super(DeenPluginSha224, self).__init__()

    def process(self, data):
        super(DeenPluginSha224, self).process(data)
        try:
            h = hashlib.new('sha224')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data


class DeenPluginSha256(DeenPlugin):
    name = 'sha256'
    display_name = 'SHA256'
    cmd_name = 'sha256'
    cmd_help = 'Hash data with SHA256'

    def __init__(self):
        super(DeenPluginSha256, self).__init__()

    def process(self, data):
        super(DeenPluginSha256, self).process(data)
        try:
            h = hashlib.new('sha256')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data


class DeenPluginSha384(DeenPlugin):
    name = 'sha384'
    display_name = 'SHA384'
    cmd_name = 'sha384'
    cmd_help = 'Hash data with SHA384'

    def __init__(self):
        super(DeenPluginSha384, self).__init__()

    def process(self, data):
        super(DeenPluginSha384, self).process(data)
        try:
            h = hashlib.new('sha384')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data


class DeenPluginSha512(DeenPlugin):
    name = 'sha512'
    display_name = 'SHA512'
    cmd_name = 'sha512'
    cmd_help = 'Hash data with SHA512'

    def __init__(self):
        super(DeenPluginSha512, self).__init__()

    def process(self, data):
        super(DeenPluginSha512, self).process(data)
        try:
            h = hashlib.new('sha512')
            h.update(data)
            data = h.hexdigest().encode()
        except ValueError as e:
            self.error = e
            self.log.error(self.error)
            self.log.debug(self.error, exc_info=True)
        return data