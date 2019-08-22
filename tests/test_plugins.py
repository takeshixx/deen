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
import zlib

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

from deen.loader import DeenPluginLoader
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
        self._plugins = DeenPluginLoader()

    def _random_str(self, length=16):
        return ''.join(random.choice(string.ascii_uppercase + string.digits)
                for _ in range(length))

    def _random_bytes(self, length=16):
        return os.urandom(length)

    def test_encode_base64(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b64encode(data_bytes)
        plugin = self._plugins.get_plugin_instance('base64')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during Base64 encoding'
        self.assertIsInstance(result, bytes,
            'Base64 encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_base64(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b64encode(data_bytes)
        plugin = self._plugins.get_plugin_instance('base64')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during Base64 decoding'
        self.assertIsInstance(result, bytes,
            'Base64 decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_encode_base64_url(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.urlsafe_b64encode(data_bytes)
        plugin = self._plugins.get_plugin_instance('base64url')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during Base64 URLsafe encoding'
        self.assertIsInstance(result, bytes,
            'Base64 URLsafe encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_base64_url(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.urlsafe_b64encode(data_bytes)
        plugin = self._plugins.get_plugin_instance('base64url')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during Base64 URLsafe decoding'
        self.assertIsInstance(result, bytes,
            'Base64 URLsafe decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_encode_base32(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b32encode(data_bytes)
        plugin = self._plugins.get_plugin_instance('base32')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during Base32 encoding'
        self.assertIsInstance(result, bytes,
            'Base32 encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_base32(self):
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b32encode(data_bytes)
        plugin = self._plugins.get_plugin_instance('base32')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during Base32 decoding'
        self.assertIsInstance(result, bytes,
            'Base32 decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_encode_base85(self):
        if sys.version_info.major != 3 or \
                sys.version_info.minor < 4:
            self.fail('Base85 support not available for the current Python version!')
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b85encode(data_bytes)
        plugin = self._plugins.get_plugin_instance('base85')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during Base85 encoding'
        self.assertIsInstance(result, bytes,
            'Base85 encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_base85(self):
        if sys.version_info.major != 3 or \
                sys.version_info.minor < 4:
            self.fail('Base85 support not available for the current Python version!')
        data_bytes = self._random_bytes()
        encoded_bytes = base64.b85encode(data_bytes)
        plugin = self._plugins.get_plugin_instance('base85')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during Base85 decoding'
        self.assertIsInstance(result, bytes,
            'Base85 decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_encode_hex(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'hex')
        plugin = self._plugins.get_plugin_instance('hex')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during hex encoding'
        self.assertIsInstance(result, bytes,
            'Hex encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_hex(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'hex')
        plugin = self._plugins.get_plugin_instance('hex')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during hex decoding'
        self.assertIsInstance(result, bytes,
            'Hex decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_encode_url(self):
        data_bytes = b'a b  c/d?'
        # urllib requires str?
        encoded_bytes = urllibparse.quote_plus(data_bytes.decode())
        plugin = self._plugins.get_plugin_instance('url')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during URL encoding'
        self.assertIsInstance(result, bytes,
            'URL encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes.encode(), result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_url(self):
        data_bytes = b'a b  c/d?'
        # urllib requires str?
        encoded_bytes = urllibparse.quote_plus(data_bytes.decode()).encode()
        plugin = self._plugins.get_plugin_instance('url')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during URL decoding'
        self.assertIsInstance(result, bytes,
            'URL decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_encode_html(self):
        data_bytes = b'<script>alert(1)</script>'
        # html module requires str?
        encoded_bytes = html_encode(data_bytes.decode())
        plugin = self._plugins.get_plugin_instance('html')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during HTML encoding'
        self.assertIsInstance(result, bytes,
            'HTML encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes.encode(), result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_html(self):
        data_bytes = b'<script>alert(1)</script>'
        # html module requires str?
        encoded_bytes = html_encode(data_bytes.decode()).encode()
        # Transformer requires bytes
        plugin = self._plugins.get_plugin_instance('html')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during HTML decoding'
        self.assertIsInstance(result, bytes,
            'HTML decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_encode_quopri(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'quopri')
        plugin = self._plugins.get_plugin_instance('quopri')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during quopri encoding'
        self.assertIsInstance(result, bytes,
            'Quopri encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_quopri(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'quopri')
        plugin = self._plugins.get_plugin_instance('quopri')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during quopri decoding'
        self.assertIsInstance(result, bytes,
            'Quopri decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_encode_uuencode(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'uu')
        plugin = self._plugins.get_plugin_instance('uuencode')
        result = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during uuencode encoding'
        self.assertIsInstance(result, bytes,
            'Uuencode encoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(encoded_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_decode_uuencode(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'uu')
        plugin = self._plugins.get_plugin_instance('uuencode')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during uuencode decoding'
        self.assertIsInstance(result, bytes,
            'Uuencode decoding result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_decode_random_bytes(self):
        data_bytes = self._random_bytes()
        for p in self._plugins.codecs:
            try:
                plugin = self._plugins.get_plugin_instance(p[0])
                plugin.unprocess(data_bytes)
            except (binascii.Error, ValueError) as e:
                pass
            except Exception as e:
                self.fail(e)

    def test_compress_gzip(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'zlib')
        plugin = self._plugins.get_plugin_instance('gzip')
        result_bytes = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during gzip compression'
        self.assertIsInstance(result_bytes, bytes,
            'Gzip compression result should be bytes or bytearray, '
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_uncompress_gzip(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'zlib')
        plugin = self._plugins.get_plugin_instance('gzip')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during gzip uncompression'
        self.assertIsInstance(result, bytes,
            'Gzip uncompression result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_compress_deflate(self):
        data_bytes = self._random_bytes()
        zlib_compress = zlib.compressobj(-1, zlib.DEFLATED, -15)
        zlib_compress.compress(data_bytes)
        encoded_bytes = zlib_compress.flush()
        plugin = self._plugins.get_plugin_instance('deflate')
        result_bytes = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during deflate compression'
        self.assertIsInstance(result_bytes, bytes,
            'Deflate compression result should be bytes or bytearray, '
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_uncompress_deflate(self):
        data_bytes = self._random_bytes()
        zlib_compress = zlib.compressobj(-1, zlib.DEFLATED, -15)
        zlib_compress.compress(data_bytes)
        encoded_bytes = zlib_compress.flush()
        plugin = self._plugins.get_plugin_instance('deflate')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during deflate uncompression'
        self.assertIsInstance(result, bytes,
            'Deflate uncompression result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_compress_bz2(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'bz2')
        plugin = self._plugins.get_plugin_instance('bzip2')
        result_bytes = plugin.process(data_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during bzip2 compression'
        self.assertIsInstance(result_bytes, bytes,
            'bzip2 compression result should be bytes or bytearray, '
            'got %s instead' % type(result_bytes))
        self.assertEqual(encoded_bytes, result_bytes)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.process, data_str), 'Unexpected exception raised')

    def test_uncompress_bz2(self):
        data_bytes = self._random_bytes()
        encoded_bytes = codecs.encode(data_bytes, 'bz2')
        plugin = self._plugins.get_plugin_instance('bzip2')
        result = plugin.unprocess(encoded_bytes)
        self.assertIsNone(plugin.error), 'An error occurred during bzip2 uncompression'
        self.assertIsInstance(result, bytes,
            'bz2 uncompression result should be bytes or bytearray, '
            'got %s instead' % type(result))
        self.assertEqual(data_bytes, result)
        data_str = self._random_str()
        self.assertRaises(TypeError, functools.partial(
            plugin.unprocess, data_str), 'Unexpected exception raised')

    def test_hashs(self):
        data_bytes = self._random_bytes()
        for hash in self._plugins.hashs:
            if hash[1].name == 'ntlm' or hash[1].name == 'mysql' or \
                    hash[1].name == 'bcrypt':
                # Skip some hash formats that are not part
                # of the hashlib module.
                continue
            plugin = self._plugins.get_plugin_instance(hash[0])
            data_hashed = plugin.process(data_bytes)
            self.assertIsNone(plugin.error, 'An error occured: ' + str(plugin.error))
            self.assertIsInstance(data_hashed, (bytes, bytearray),
              'Hashing result should be bytes or bytearray, ' \
              'got %s instead' % type(data_hashed))
            h = hashlib.new(hash[1].name)
            h.update(data_bytes)
            self.assertEqual(h.hexdigest().encode(), data_hashed, 'Hash calculation failed for ' + hash[0])

    def test_hashs_ntlm(self):
        data_str = self._random_str()
        plugin = self._plugins.get_plugin_instance('ntlm')
        data_hashed = plugin.process(data_str.encode())
        self.assertIsNone(plugin.error, 'An error occured: ' + str(plugin.error))
        self.assertIsInstance(data_hashed, (bytes, bytearray),
                              'Hashing result should be bytes or bytearray, '
                              'got %s instead' % type(data_hashed))
        h = hashlib.new('md4')
        h.update(data_str.encode('utf-16-le'))
        self.assertEqual(h.hexdigest().encode(), data_hashed)

    def test_hashs_mysql(self):
        data = self._random_bytes()
        plugin = self._plugins.get_plugin_instance('mysql')
        data_hashed = plugin.process(data)
        self.assertIsNone(plugin.error, 'An error occured: ' + str(plugin.error))
        self.assertIsInstance(data_hashed, (bytes, bytearray),
                              'Hashing result should be bytes or bytearray, '
                              'got %s instead' % type(data_hashed))
        h1 = hashlib.new('sha1')
        h2 = hashlib.new('sha1')
        h1.update(data)
        h2.update(h1.digest())
        self.assertEqual(h2.hexdigest().encode(), data_hashed)

    def test_x509_format(self):
        self.assertTrue(OPENSSL, 'pyOpenSSL is not available!')
        certificate = CERTIFICATE
        plugin = self._plugins.get_plugin_instance('x509certificate')
        try:
            formatted = plugin.process(certificate)
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(formatted)
        self.assertIsNone(plugin.error)

    def test_x509_format_incomplete(self):
        self.assertTrue(OPENSSL, 'pyOpenSSL is not available!')
        certificate = CERTIFICATE.replace(b'-----BEGIN CERTIFICATE-----\n', b'') \
                                 .replace(b'\n-----END CERTIFICATE-----', b'')
        plugin = self._plugins.get_plugin_instance('x509certificate')
        try:
            formatted = plugin.process(certificate)
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(formatted)
        self.assertIsNone(plugin.error)

    def test_x509_format_der(self):
        self.assertTrue(OPENSSL, 'pyOpenSSL is not available!')
        certificate = CERTIFICATE.replace(b'-----BEGIN CERTIFICATE-----\n', b'') \
                                 .replace(b'\n-----END CERTIFICATE-----', b'') \
                                 .replace(b'\n', b'')
        certificate = base64.b64decode(certificate)
        plugin = self._plugins.get_plugin_instance('x509certificate')
        try:
            formatted = plugin.process(certificate)
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(formatted)
        self.assertIsNone(plugin.error)

    def test_x509_format_invalid(self):
        self.assertTrue(OPENSSL, 'pyOpenSSL is not available!')
        certificate = self._random_bytes(32)
        plugin = self._plugins.get_plugin_instance('x509certificate')
        try:
            formatted = plugin.process(certificate)
        except Exception as e:
            self.fail('Unhandled exception in x509certificate: ' + str(e))
        else:
            msg = 'x509certificate failed without setting plugin.error'
            self.assertIsNotNone(plugin.error, msg)
            msg = 'x509certificate invalid certificate did not return TransformException'
            self.assertIsInstance(plugin.error, TransformException, msg)

    def test_format_xml(self):
        doc = (b'<?xml version="1.0" encoding="UTF-8"?><note>'
               b'<to>Tove</to><from>Jani</from><heading>Reminder'
               b'</heading><body>Don\'t forget me this weekend!'
               b'</body></note>')
        plugin = self._plugins.get_plugin_instance('xml_formatter')
        try:
            plugin.process(doc)
        except Exception as e:
            self.fail(e)
        self.assertIsNone(plugin.error)

    def test_format_xml_invalid(self):
        doc = (b'<?xml version="1.0" encoding="UTF-8"?><note>'
               b'<to>Tove</ERRORto><from>Jani</from><headingReminder'
               b'</heading><body>Don\'t forget me this weekend!'
               b'</bodyXXX></note>')
        plugin = self._plugins.get_plugin_instance('xml_formatter')
        try:
            plugin.process(doc)
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(plugin.error)

    def test_format_html(self):
        doc = (b'<!DOCTYPE html><html><body><h1>My First Heading'
               b'</h1><p>My first paragraph.</p></body></html>')
        plugin = self._plugins.get_plugin_instance('html_formatter')
        try:
            plugin.process(doc)
        except Exception as e:
            self.fail(e)
        self.assertIsNone(plugin.error)

    def test_format_html_invalid(self):
        doc = (b'<!DOCTYPE html><html><div><h1>My First Heading'
               b'</h1><p>My first paragraph.</p</body></html>')
        plugin = self._plugins.get_plugin_instance('html_formatter')
        try:
            plugin.process(doc)
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(plugin.error)

    def test_format_json(self):
        doc = (b'{"employees":[{"firstName":"John", "lastName":'
               b'"Doe"},{"firstName":"Anna", "lastName":"Smith"}'
               b',{"firstName":"Peter", "lastName":"Jones"}]}')
        plugin = self._plugins.get_plugin_instance('json_formatter')
        try:
            plugin.process(doc)
        except Exception as e:
            self.fail(e)
        self.assertIsNone(plugin.error)

    def test_format_json_invalid(self):
        doc = (b'{"employees":[{{"firstName":"John", "lastName":'
               b'"Doe"},{"firstName":"Anna", "lastName""Smith"}'
               b',{"firstName":"Peter, "lastName":"Jones"}]}')
        plugin = self._plugins.get_plugin_instance('json_formatter')
        try:
            plugin.process(doc)
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(plugin.error)

    def test_format_js_beautifier(self):
        code = (b'var _0xe272=["\x53\x61\x79\x48\x65\x6C\x6C\x6F","\x48\x65\x6C\x6C\x6F\x20'
                b'\x57\x6F\x72\x6C\x64"];function NewObject(){this[_0xe272[0]]= function(_'
                b'0x5120x2){alert(_0x5120x2)}}var obj= new NewObject();obj.SayHello(_0xe27'
                b'2[1])')
        plugin = self._plugins.get_plugin_instance('jsbeautifier_formatter')
        try:
            plugin.process(code)
        except Exception as e:
            print(e)
            self.fail(e)
        self.assertIsNone(plugin.error)

    def test_format_js_beautifier_invalid(self):
        code = self._random_bytes(32)
        plugin = self._plugins.get_plugin_instance('jsbeautifier_formatter')
        try:
            plugin.process(code)
        except Exception as e:
            self.fail(e)
        self.assertIsNotNone(plugin.error)


if __name__ == '__main__':
    unittest.main()
