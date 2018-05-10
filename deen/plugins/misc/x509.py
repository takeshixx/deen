import logging
import base64
import binascii
try:
    import OpenSSL.crypto
    OPENSSL = True
except ImportError:
    OPENSSL = False

from deen.exceptions import *
from .. import DeenPlugin

LOGGER = logging.getLogger(__name__)


class DeenPluginX509Certificate(DeenPlugin):
    name = 'x509certificate'
    display_name = 'X.509 Certificate'
    aliases = ['x509']

    def __init__(self):
        super(DeenPluginX509Certificate, self).__init__()

    @property
    def certificate(self):
        return self._certificate

    @certificate.setter
    def certificate(self, data):
        if not OPENSSL:
            LOGGER.warning('pyOpenSSL is not available')
            return
        if not b'-----BEGIN' in data or \
            not b'-----END' in data:
            # Check if data is Base64 encoded
            try:
                base64.b64decode(data.replace(b'\n', b''), validate=True)
            except binascii.Error as e:
                LOGGER.error(e)
                # If data is not encoded, encode it
                data = base64.b64encode(data)
        try:
            data = data.decode()
        except UnicodeDecodeError:
            LOGGER.error('Invalid certificate encoding')
            return
        data = data.strip()
        if not '-----BEGIN CERTIFICATE-----' in data:
            LOGGER.warning('Missing certificate prefix')
            data = '-----BEGIN CERTIFICATE-----\n' + data
        if not '-----END CERTIFICATE-----' in data:
            LOGGER.warning('Missing certificate suffix')
            data = data + '\n-----END CERTIFICATE-----'
        self._certificate = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, data)

    def process(self, data):
        super(DeenPluginX509Certificate, self).process(data)
        self.certificate = data
        if not self._certificate:
            self.error = TransformException('Invalid certificate')
            return
        if OPENSSL and self._certificate is not None:
            out = bytearray()
            out.extend(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_TEXT, self.certificate))
            out.extend(b'\n')
            out.extend(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, self.certificate))
            return out
        elif not OPENSSL:
            LOGGER.warning('pyOpenSSL is not available')
        return data
