import logging
try:
    import OpenSSL.crypto
    OPENSSL = True
except ImportError:
    OPENSSL = False

from deen.exceptions import *

LOGGER = logging.getLogger(__name__)


class X509Certificate():
    def __init__(self):
        self._certificate = None

    @property
    def certificate(self):
        return self._certificate

    @certificate.setter
    def certificate(self, data):
        if not OPENSSL:
            LOGGER.warning('pyOpenSSL is not available')
            return
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

    def decode(self):
        if not self._certificate:
            raise TransformException('Invalid certificate')
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
