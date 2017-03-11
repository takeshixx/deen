import base64
import binascii
import codecs
import hashlib
import logging
import zlib

try:
    # Python 3
    import urllib.parse as urllibparse
except ImportError:
    # Python 2
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

from deen.constants import *

LOGGER = logging.getLogger(__name__)


class DeenTransformer(object):
    """A generic wrapper class that provides
    various transformation functions."""
    def _in_list(self, data, const_list):
        for item in const_list:
            if data.lower() == item.lower():
                return True
        else:
            return False

    def encode(self, enc, data):
        assert isinstance(data, (bytearray, bytes))
        enc = enc.lower()
        assert self._in_list(enc, ENCODINGS),\
            'Unknown encoding %s' % enc
        if enc == 'base64':
            output = base64.b64encode(data)
        elif enc == 'base64 url':
            output = base64.urlsafe_b64encode(data)
        elif enc == 'base32':
            output = base64.b32encode(data)
        elif enc == 'base85':
            output = base64.b85encode(data)
        elif enc == 'hex':
            output = codecs.encode(data, 'hex')
        elif enc == 'url':
            # urllib requires str?
            output = urllibparse.quote_plus(data.decode())
            output = output.encode()
        elif enc == 'html':
            # html module requires str?
            output = html_encode(data.decode())
            output = output.encode()
        elif enc == 'rot13':
            output = codecs.encode(data.decode(), 'rot_13')
        elif enc == 'utf8':
            output = codecs.encode(data.decode(), 'utf8')
        elif enc == 'utf16':
            output = codecs.encode(data.decode(), 'utf16')
        else:
            output = data
        return output

    def decode(self, enc, data):
        enc = enc.lower()
        assert self._in_list(enc, ENCODINGS),\
            'Unknown encoding %s' % enc
        assert data is not None, 'Data is None'
        assert isinstance(data, (bytes, bytearray)),\
            'Wrong data type %s' % type(data)
        decode_error = None
        if enc == 'base64':
            # Remove new lines and carriage returns from
            # Base64 encoded data.
            data = data.replace(b'\n', b'').replace(b'\r', b'')
            try:
                output = base64.b64decode(data)
            except binascii.Error as e:
                decode_error = e
                output = data
        elif enc == 'base64 url':
            # Remove new lines and carriage returns from
            # Base64 encoded data.
            data = data.replace(b'\n', b'').replace(b'\r', b'')
            try:
                output = base64.urlsafe_b64decode(data)
            except binascii.Error as e:
                decode_error = e
                output = data
        elif enc == 'base32':
            # Remove new lines and carriage returns from
            # Base32 encoded data.
            data = data.replace(b'\n', b'').replace(b'\r', b'')
            try:
                output = base64.b32decode(data)
            except binascii.Error as e:
                decode_error = e
                output = data
        elif enc == 'base85':
            # Remove new lines and carriage returns from
            # Base85 encoded data.
            data = data.replace(b'\n', b'').replace(b'\r', b'')
            try:
                output = base64.b85decode(data)
            except binascii.Error as e:
                decode_error = e
                output = data
        elif enc == 'hex':
            # Remove new lines and carriage returns from
            # Base64 encoded data.
            data = data.replace(b'\n', b'').replace(b'\r', b'')
            try:
                output = codecs.decode(data, 'hex')
            except (binascii.Error, TypeError) as e:
                decode_error = e
                output = data
        elif enc == 'url':
            try:
                output = urllibparse.unquote_plus(data.decode())
                output = output.encode()
            except TypeError as e:
                decode_error = e
                output = data
        elif enc == 'html':
            try:
                output = html_decode(data.decode())
                output = output.encode()
            except TypeError as e:
                decode_error = e
                output = data
        elif enc == 'rot13':
            output = codecs.decode(data.decode(), 'rot_13')
        else:
            output = data
        return output, decode_error

    def compress(self, comp, data):
        comp = comp.lower()
        assert self._in_list(comp, COMPRESSIONS),\
            'Unknown compression %s' % comp
        assert data is not None, 'Data is None'
        assert isinstance(data, (bytes, bytearray)),\
            'Wrong data type %s' % type(data)
        if comp == 'gzip':
            try:
                output = codecs.encode(data, 'zlib')
            except TypeError:
                # Python 2 does not like bytearrays
                output = codecs.encode(buffer(data), 'zlib')
        elif comp == 'bz2':
            output = codecs.encode(data, 'bz2')
        else:
            output = data
        return output

    def uncompress(self, comp, data):
        comp = comp.lower()
        assert self._in_list(comp, COMPRESSIONS),\
            'Unknown compression %s' % comp
        assert data is not None, 'Data is None'
        assert isinstance(data, (bytes, bytearray)),\
            'Wrong data type %s' % type(data)
        decode_error = None
        if comp == 'gzip':
            try:
                output = codecs.decode(data, 'zlib')
            except zlib.error as e:
                decode_error = e
                output = data
            except TypeError:
                try:
                    # Python 2 does not like bytearrays
                    output = codecs.decode(buffer(data), 'zlib')
                except zlib.error as e:
                    decode_error = e
                    output = data
        elif comp == 'bz2':
            try:
                output = codecs.decode(data, 'bz2')
            except (OSError, IOError) as e:
                decode_error = e
                output = data
        else:
            output = data
        return output, decode_error

    def hash(self, hash_algo, data):
        hash_algo = hash_algo.lower()
        hash_error = None
        assert data is not None, 'Data is None'
        assert isinstance(data, (bytes, bytearray)),\
            'Wrong data type %s' % type(data)
        if hash_algo == 'all':
            output = bytearray()
            for _hash in HASHS:
                if _hash == 'NTLM':
                    continue
                try:
                    h = hashlib.new(_hash.lower())
                    h.update(data)
                    output.extend(_hash.encode() + b':\t')
                    output.extend(h.hexdigest().encode())
                    output.extend(b'\n')
                except ValueError:
                    continue
        elif hash_algo == 'ntlm':
            h = hashlib.new('md4')
            data = data.decode()
            h.update(data.encode('utf-16-le'))
            output = h.hexdigest().encode()
        elif self._in_list(hash_algo, HASHS):
            try:
                h = hashlib.new(hash_algo)
                h.update(data)
                output = h.hexdigest().encode()
            except ValueError as e:
                hash_error = e
                output = data
        else:
            output = data
        return output, hash_error
