import os
import unittest
import codecs
import base64
import random
import string
import functools
import hashlib
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

from deen.transformers.core import DeenTransformer
from deen.transformers.x509 import X509Certificate
from deen.constants import HASHS


class TestTransformers(unittest.TestCase):
    def setUp(self):
        self._transformer = DeenTransformer()
        self._x509_certificate = X509Certificate()

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


if __name__ == '__main__':
    unittest.main()
