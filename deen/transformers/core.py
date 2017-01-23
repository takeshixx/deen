import logging
import hashlib
import base64
import codecs
import binascii
import zlib
import cgi
try:
    import urllib.parse as urllibparse
except ImportError:
    import urllib as urllibparse
try:
    from html.parser import HTMLParser
except ImportError:
    from HTMLParser import HTMLParser
try:
    import OpenSSL.crypto
    OPENSSL = True
except ImportError:
    OPENSSL = False

from deen.core import *

LOGGER = logging.getLogger(__name__)

# TODO: make transformer checks non-case-sensitive
class DeenTransformer(object):
    """A generic wrapper class that provides various tranformation
    functions."""
    def _in_dict(self, data, core_dict):
        included = False
        for item in core_dict:
            if data.lower() == item.lower():
                included = True
                break
        return included

    def encode(self, enc, data):
        enc = enc.lower()
        assert self._in_dict(enc, ENCODINGS), 'Unknown encoding %s' % enc
        if enc == 'base64':
            output = base64.b64encode(data)
        elif enc == 'hex':
            output = codecs.encode(data, 'hex')
        elif enc == 'url':
            output = urllibparse.quote_plus(data.decode())
        elif enc == 'html':
            output = cgi.escape(data.decode())
        elif enc == 'gzip':
            output = codecs.encode(data, 'zlib')
        elif enc == 'bz2':
            output = codecs.encode(data, 'bz2')
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
        assert self._in_dict(enc, ENCODINGS), 'Unknown encoding %s' % enc
        decode_error = None
        if enc == 'base64':
            try:
                output = base64.b64decode(data.replace(b'\n', b''))
            except binascii.Error as e:
                decode_error = e
                output = data
        elif enc == 'hex':
            try:
                output = codecs.decode(data, 'hex')
            except binascii.Error as e:
                decode_error = e
                output = data
        elif enc == 'url':
            try:
                output = urllibparse.unquote_plus(data.decode())
            except TypeError as e:
                decode_error = e
                output = data
        elif enc == 'html':
            h = HTMLParser()
            try:
                output = h.unescape(data.decode())
            except TypeError as e:
                decode_error = e
                output = data
        elif enc == 'gzip':
            try:
                output = codecs.decode(data.decode(), 'zlib')
            except zlib.error as e:
                decode_error = e
                output = data
        elif enc == 'bz2':
            try:
                output = codecs.decode(data.decode(), 'bz2')
            except OSError as e:
                decode_error = e
                output = data
        elif enc == 'rot13':
            output = codecs.decode(data.decode(), 'rot_13')
        else:
            output = data
        return output, decode_error

    def compress(self, comp, data):
        comp = comp.lower()
        assert self._in_dict(comp, COMPRESSIONS), 'Unknown compression %s' % comp
        if comp == 'gzip':
            output = codecs.encode(data, 'zlib')
        elif comp == 'bz2':
            output = codecs.encode(data, 'bz2')
        else:
            output = data
        return output

    def uncompress(self, comp, data):
        comp = comp.lower()
        assert self._in_dict(comp, COMPRESSIONS), 'Unknown compression %s' % comp
        decode_error = None
        if comp == 'gzip':
            try:
                output = codecs.decode(data, 'zlib')
            except zlib.error as e:
                decode_error = e
                output = data
        elif comp == 'bz2':
            try:
                output = codecs.decode(data, 'bz2')
            except OSError as e:
                decode_error = e
                output = data
        else:
            output = data
        return output, decode_error

    def hash(self, hash, data):
        hash = hash.lower()
        if hash == 'all':
            output = ''
            for _hash in HASHS:
                output += '{}:\t'.format(_hash)
                h = hashlib.new(_hash.lower())
                h.update(data)
                output += h.hexdigest()
                output += '\n'
        elif self._in_dict(hash, HASHS):
            h = hashlib.new(hash)
            h.update(data)
            output = h.hexdigest()
        else:
            output = data
        return output


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
