import os
import sys
import unittest
import codecs
import base64
import random
import string
import functools
import hashlib
import binascii
try:
    import urllib.parse as urllibparse
except ImportError:
    import urllib as urllibparse
try:
    # Python 3
    import html
    html_encode = html.escape
    html_decode = html.unescape
except ImportError:
    # Python 2
    import cgi
    html_encode = cgi.escape
    from HTMLParser import HTMLParser
    html = HTMLParser()
    html_decode = html.unescape
try:
    from OpenSSL import crypto
except Exception:
    OPENSSL = False
else:
    OPENSSL = True

from deen.transformers.core import DeenTransformer
from deen.transformers.x509 import X509Certificate
from deen.constants import HASHS, ENCODINGS
from deen.exceptions import *

CERTIFICATE = b"""-----BEGIN CERTIFICATE-----
MIIHeTCCBmGgAwIBAgIQC/20CQrXteZAwwsWyVKaJzANBgkqhkiG9w0BAQsFADB1
MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3
d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk
IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTE2MDMxMDAwMDAwMFoXDTE4MDUxNzEy
MDAwMFowgf0xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYB
BAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQITCERlbGF3YXJlMRAwDgYDVQQF
Ewc1MTU3NTUwMSQwIgYDVQQJExs4OCBDb2xpbiBQIEtlbGx5LCBKciBTdHJlZXQx
DjAMBgNVBBETBTk0MTA3MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5p
YTEWMBQGA1UEBxMNU2FuIEZyYW5jaXNjbzEVMBMGA1UEChMMR2l0SHViLCBJbmMu
MRMwEQYDVQQDEwpnaXRodWIuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA54hc8pZclxgcupjiA/F/OZGRwm/ZlucoQGTNTKmBEgNsrn/mxhngWmPw
bAvUaLP//T79Jc+1WXMpxMiz9PK6yZRRFuIo0d2bx423NA6hOL2RTtbnfs+y0PFS
/YTpQSelTuq+Fuwts5v6aAweNyMcYD0HBybkkdosFoDccBNzJ92Ac8I5EVDUc3Or
/4jSyZwzxu9kdmBlBzeHMvsqdH8SX9mNahXtXxRpwZnBiUjw36PgN+s9GLWGrafd
02T0ux9Yzd5ezkMxukqEAQ7AKIIijvaWPAJbK/52XLhIy2vpGNylyni/DQD18bBP
T+ZG1uv0QQP9LuY/joO+FKDOTler4wIDAQABo4IDejCCA3YwHwYDVR0jBBgwFoAU
PdNQpdagre7zSmAKZdMh1Pj41g8wHQYDVR0OBBYEFIhcSGcZzKB2WS0RecO+oqyH
IidbMCUGA1UdEQQeMByCCmdpdGh1Yi5jb22CDnd3dy5naXRodWIuY29tMA4GA1Ud
DwEB/wQEAwIFoDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwdQYDVR0f
BG4wbDA0oDKgMIYuaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL3NoYTItZXYtc2Vy
dmVyLWcxLmNybDA0oDKgMIYuaHR0cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTIt
ZXYtc2VydmVyLWcxLmNybDBLBgNVHSAERDBCMDcGCWCGSAGG/WwCATAqMCgGCCsG
AQUFBwIBFhxodHRwczovL3d3dy5kaWdpY2VydC5jb20vQ1BTMAcGBWeBDAEBMIGI
BggrBgEFBQcBAQR8MHowJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0
LmNvbTBSBggrBgEFBQcwAoZGaHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0Rp
Z2lDZXJ0U0hBMkV4dGVuZGVkVmFsaWRhdGlvblNlcnZlckNBLmNydDAMBgNVHRMB
Af8EAjAAMIIBfwYKKwYBBAHWeQIEAgSCAW8EggFrAWkAdgCkuQmQtBhYFIe7E6LM
Z3AKPDWYBPkb37jjd80OyA3cEAAAAVNhieoeAAAEAwBHMEUCIQCHHSEY/ROK2/sO
ljbKaNEcKWz6BxHJNPOtjSyuVnSn4QIgJ6RqvYbSX1vKLeX7vpnOfCAfS2Y8lB5R
NMwk6us2QiAAdgBo9pj4H2SCvjqM7rkoHUz8cVFdZ5PURNEKZ6y7T0/7xAAAAVNh
iennAAAEAwBHMEUCIQDZpd5S+3to8k7lcDeWBhiJASiYTk2rNAT26lVaM3xhWwIg
NUqrkIODZpRg+khhp8ag65B8mu0p4JUAmkRDbiYnRvYAdwBWFAaaL9fC7NP14b1E
sj7HRna5vJkRXMDvlJhV1onQ3QAAAVNhieqZAAAEAwBIMEYCIQDnm3WStlvE99GC
izSx+UGtGmQk2WTokoPgo1hfiv8zIAIhAPrYeXrBgseA9jUWWoB4IvmcZtshjXso
nT8MIG1u1zF8MA0GCSqGSIb3DQEBCwUAA4IBAQCLbNtkxuspqycq8h1EpbmAX0wM
5DoW7hM/FVdz4LJ3Kmftyk1yd8j/PSxRrAQN2Mr/frKeK8NE1cMji32mJbBqpWtK
/+wC+avPplBUbNpzP53cuTMF/QssxItPGNP5/OT9Aj1BxA/NofWZKh4ufV7cz3pY
RDS4BF+EEFQ4l5GY+yp4WJA/xSvYsTHWeWxRD1/nl62/Rd9FN2NkacRVozCxRVle
FrBHTFxqIP6kDnxiLElBrZngtY07ietaYZVLQN/ETyqLQftsf8TecwTklbjvm8NT
JqbaIVifYwqwNN+4lRxS3F5lNlA/il12IOgbRioLI62o8G0DaEUQgHNf8vSG
-----END CERTIFICATE-----"""


class TestTransformers(unittest.TestCase):
    def setUp(self):
        self._transformer = DeenTransformer()

    def _random_str(self, length=16):
        return ''.join(random.choice(string.ascii_uppercase + string.digits)
                for _ in range(length))

    def _random_bytes(self, length=16):
        return os.urandom(length)

    def test_encode_base64(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b64encode(data_bytes)
        result_bytes = self._transformer.encode('base64', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'Base64 encoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.encode, 'base64', data_str),
                          'Unexpected exception raised')

    def test_decode_base64(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b64encode(data_bytes)
        result = self._transformer.decode('base64', encoded_bytes)
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during Base64 decoding'
        self.assertIsInstance(result[0], bytes,
            'Base64 decoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.decode, 'base64', data_str),
                        'Unexpected exception raised')

    def test_encode_base64_url(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.urlsafe_b64encode(data_bytes)
        result_bytes = self._transformer.encode('base64 url', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'Base64 URLsafe encoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.encode, 'base64 url', data_str),
                          'Unexpected exception raised')

    def test_decode_base64_url(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.urlsafe_b64encode(data_bytes)
        result = self._transformer.decode('base64 url', encoded_bytes)
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during Base64 URLsafe decoding'
        self.assertIsInstance(result[0], bytes,
            'Base64 URLsafe decoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.decode, 'base64 url', data_str),
                        'Unexpected exception raised')

    def test_encode_base32(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b32encode(data_bytes)
        result_bytes = self._transformer.encode('base32', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'Base32 encoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.encode, 'base32', data_str),
                          'Unexpected exception raised')

    def test_decode_base32(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b32encode(data_bytes)
        result = self._transformer.decode('base32', encoded_bytes)
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during Base32 decoding'
        self.assertIsInstance(result[0], bytes,
            'Base32 decoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.decode, 'base32', data_str),
                        'Unexpected exception raised')

    def test_encode_base85(self):
        if sys.version_info.major != 3 or \
                sys.version_info.minor < 4:
            self.fail('Base85 support not available for the current Python version!')
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b85encode(data_bytes)
        result_bytes = self._transformer.encode('base85', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'Base85 encoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.encode, 'base85', data_str),
                          'Unexpected exception raised')

    def test_decode_base85(self):
        if sys.version_info.major != 3 or \
                sys.version_info.minor < 4:
            self.fail('Base85 support not available for the current Python version!')
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b85encode(data_bytes)
        result = self._transformer.decode('base85', encoded_bytes)
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during Base85 decoding'
        self.assertIsInstance(result[0], bytes,
            'Base85 decoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.decode, 'base85', data_str),
                        'Unexpected exception raised')

    def test_encode_hex(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'hex')
        result_bytes = self._transformer.encode('hex', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'Hex encoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.encode, 'hex', data_str),
                          'Unexpected exception raised')

    def test_decode_hex(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'hex')
        result = self._transformer.decode('hex', encoded_bytes)
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during hex decoding'
        self.assertIsInstance(result[0], bytes,
            'Hex decoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.decode, 'hex', data_str),
                        'Unexpected exception raised')

    def test_encode_url(self):
        data_bytes = b'a b  c/d?'
        # urllib requires str?
        encoded_bytes = urllibparse.quote_plus(data_bytes.decode())
        result_bytes = self._transformer.encode('url', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'URL encoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes.encode(), result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.encode, 'url', data_str),
                          'Unexpected exception raised')

    def test_decode_url(self):
        data_bytes = b'a b  c/d?'
        # urllib requires str?
        encoded_bytes = urllibparse.quote_plus(data_bytes.decode())
        result = self._transformer.decode('url', encoded_bytes.encode())
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during hex decoding'
        self.assertIsInstance(result[0], bytes,
            'URL decoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.decode, 'url', data_str),
                        'Unexpected exception raised')

    def test_encode_html(self):
        data_bytes = b'<script>alert(1)</script>'
        # html module requires str?
        encoded_bytes = html_encode(data_bytes.decode())
        result_bytes = self._transformer.encode('html', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'HTML encoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes.encode(), result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.encode, 'html', data_str),
                          'Unexpected exception raised')

    def test_decode_html(self):
        data_bytes = b'<script>alert(1)</script>'
        # html module requires str?
        encoded_bytes = html_encode(data_bytes.decode())
        # Transformer requires bytes
        result = self._transformer.decode('html', encoded_bytes.encode())
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during HTML decoding'
        self.assertIsInstance(result[0], bytes,
            'HTML decoding result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.decode, 'html', data_str),
                        'Unexpected exception raised')

    def test_decode_random_bytes(self):
        data_bytes = self._random_bytes()
        for e in ENCODINGS:
            try:
                self._transformer.decode(e, data_bytes)
            except (binascii.Error, ValueError) as e:
                pass
            except Exception as e:
                self.fail(e)

    def test_compress_gzip(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'zlib')
        result_bytes = self._transformer.compress('gzip', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'Gzip compression result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.compress, 'gzip', data_str),
                          'Unexpected exception raised')

    def test_uncompress_gzip(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'zlib')
        result = self._transformer.uncompress('gzip', encoded_bytes)
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during Gzip uncompression'
        self.assertIsInstance(result[0], bytes,
            'Gzip uncompression result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.uncompress, 'gzip', data_str),
                        'Unexpected exception raised')

    def test_compress_bz2(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'bz2')
        result_bytes = self._transformer.compress('bz2', data_bytes)
        self.assertIsInstance(result_bytes, bytes,
            'bz2 compression result should be bytes or bytearray, ' \
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.compress, 'bz2', data_str),
                          'Unexpected exception raised')

    def test_uncompress_bz2(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'bz2')
        result = self._transformer.uncompress('bz2', encoded_bytes)
        self.assertIsInstance(result, tuple)
        self.assertIsNone(result[1]), 'An error occurred during bz2 uncompression'
        self.assertIsInstance(result[0], bytes,
            'bz2 uncompression result should be bytes or bytearray, ' \
            'got %s instead' % type(result[0]))
        self.assertEqual(data_bytes, result[0])
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            self._transformer.uncompress, 'bz2', data_str),
                        'Unexpected exception raised')

    def test_hashs(self):
        data_bytes = self._random_bytes()
        for hash in HASHS:
            if hash == 'NTLM':
                # Skip NTLM hash for byte input
                continue
            data_hashed, error = self._transformer.hash(hash, data_bytes)
            self.assertIsNone(error, 'An error occured: ' + str(error))
            self.assertIsInstance(data_hashed, (bytes, bytearray),
              'Hashing result should be bytes or bytearray, ' \
              'got %s instead' % type(data_hashed))
            h = hashlib.new(hash.lower())
            h.update(data_bytes)
            self.assertEqual(h.hexdigest().encode(), data_hashed)

    def test_hashs_ntlm(self):
        data_str = self._random_str()
        data_hashed, error = self._transformer.hash('ntlm', data_str.encode())
        self.assertIsNone(error, 'An error occured: ' + str(error))
        self.assertIsInstance(data_hashed, (bytes, bytearray),
                              'Hashing result should be bytes or bytearray, ' \
                              'got %s instead' % type(data_hashed))
        h = hashlib.new('md4')
        h.update(data_str.encode('utf-16-le'))
        self.assertEqual(h.hexdigest().encode(), data_hashed)

    def test_x509_format(self):
        self.assertTrue(OPENSSL, 'pyOpenSSL is not available!')
        certificate = CERTIFICATE
        transformer = X509Certificate()
        try:
            transformer.certificate = certificate
            formatted = transformer.decode()
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(formatted)

    def test_x509_format_incomplete(self):
        self.assertTrue(OPENSSL, 'pyOpenSSL is not available!')
        certificate = CERTIFICATE.replace(b'-----BEGIN CERTIFICATE-----\n', b'') \
                                 .replace(b'\n-----END CERTIFICATE-----', b'')
        transformer = X509Certificate()
        try:
            transformer.certificate = certificate
            formatted = transformer.decode()
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(formatted)

    def test_x509_format_der(self):
        self.assertTrue(OPENSSL, 'pyOpenSSL is not available!')
        certificate = CERTIFICATE.replace(b'-----BEGIN CERTIFICATE-----\n', b'') \
                                 .replace(b'\n-----END CERTIFICATE-----', b'') \
                                 .replace(b'\n', b'')
        certificate = base64.b64decode(certificate)
        transformer = X509Certificate()
        try:
            transformer.certificate = certificate
            formatted = transformer.decode()
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(formatted)

    def test_x509_format_invalid(self):
        self.assertTrue(OPENSSL, 'pyOpenSSL is not available!')
        certificate = self._random_bytes(32)
        transformer = X509Certificate()
        try:
            transformer.certificate = certificate
        except crypto.Error:
            pass
        else:
            try:
                transformer.decode()
            except TransformException:
                pass
            else:
                self.fail('Invalid certificate does not raise TransformException!')


if __name__ == '__main__':
    unittest.main()
