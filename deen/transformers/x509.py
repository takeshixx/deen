import logging
try:
    import OpenSSL.crypto
    OPENSSL = True
except ImportError:
    OPENSSL = False

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
            return
        data = data.strip()
        if not b'-----BEGIN CERTIFICATE-----' in data:
            LOGGER.warning('Missing certificate prefix')
            data = b'-----BEGIN CERTIFICATE-----\n' + data
        if not b'-----END CERTIFICATE-----' in data:
            LOGGER.warning('Missing certificate suffix')
            data = data + b'\n-----END CERTIFICATE-----'
        self._certificate = OpenSSL.crypto.load_certificate(
            OpenSSL.crypto.FILETYPE_PEM, data.decode())

    def decode(self):
        if OPENSSL:
            out = bytearray()
            out.extend(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_TEXT, self.certificate))
            out.extend(b'\n')
            out.extend(OpenSSL.crypto.dump_certificate(
                OpenSSL.crypto.FILETYPE_PEM, self.certificate))
            return out
