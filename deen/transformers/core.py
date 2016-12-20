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

from deen.core import *

LOGGER = logging.getLogger(__name__)


class DeenTransformer(object):
    """A generic wrapper class that provides various tranformation
    functions."""
    def encode(self, enc, data):
        assert enc in ENCODINGS, 'Unknown encoding %s' % enc
        if enc == 'base64':
            output = base64.b64encode(data)
        elif enc == 'Hex':
            output = codecs.encode(data, 'hex')
        elif enc == 'URL':
            output = urllibparse.quote_plus(data.decode())
        elif enc == 'HTML':
            output = cgi.escape(data.decode())
        elif enc == 'Gzip':
            output = codecs.encode(data, 'zlib')
        elif enc == 'Bz2':
            output = codecs.encode(data, 'bz2')
        elif enc == 'Rot13':
            output = codecs.encode(data.decode(), 'rot_13')
        elif enc == 'UTF8':
            output = codecs.encode(data.decode(), 'utf8')
        elif enc == 'UTF16':
            output = codecs.encode(data.decode(), 'utf16')
        else:
            output = data
        return output

    def decode(self, enc, data):
        assert enc in ENCODINGS, 'Unknown encoding %s' % enc
        decode_error = None
        if enc == 'Base64':
            try:
                output = base64.b64decode(data.replace(b'\n', b''))
            except binascii.Error as e:
                decode_error = e
                output = data
        elif enc == 'Hex':
            try:
                output = codecs.decode(data, 'hex')
            except binascii.Error as e:
                decode_error = e
                output = data
        elif enc == 'URL':
            try:
                output = urllibparse.unquote_plus(data.decode())
            except TypeError as e:
                decode_error = e
                output = data
        elif enc == 'HTML':
            h = HTMLParser()
            try:
                output = h.unescape(data.decode())
            except TypeError as e:
                decode_error = e
                output = data
        elif enc == 'Gzip':
            try:
                output = codecs.decode(data.decode(), 'zlib')
            except zlib.error as e:
                decode_error = e
                output = data
        elif enc == 'Bz2':
            try:
                output = codecs.decode(data.decode(), 'bz2')
            except OSError as e:
                decode_error = e
                output = data
        elif enc == 'Rot13':
            output = codecs.decode(data.decode(), 'rot_13')
        else:
            output = data
        return output, decode_error

    def compress(self, comp, data):
        assert comp in COMPRESSIONS, 'Unknown compression %s' % comp
        if comp == 'Gzip':
            output = codecs.encode(data, 'zlib')
        elif comp == 'Bz2':
            output = codecs.encode(data, 'bz2')
        else:
            output = data
        return output

    def uncompress(self, comp, data):
        assert comp in COMPRESSIONS, 'Unknown compression %s' % comp
        decode_error = None
        if comp == 'Gzip':
            try:
                output = codecs.decode(data, 'zlib')
            except zlib.error as e:
                decode_error = e
                output = data
        elif comp == 'Bz2':
            try:
                output = codecs.decode(data, 'bz2')
            except OSError as e:
                decode_error = e
                output = data
        else:
            output = data
        return output, decode_error

    def hash(self, hash, data):
        assert hash in HASHS, 'Unknown hash %s' % hash
        if hash == 'ALL':
            output = ''
            for _hash in HASHS:
                output += '{}:\t'.format(_hash)
                h = hashlib.new(_hash.lower())
                h.update(data)
                output += h.hexdigest()
                output += '\n'
        elif hash in HASHS:
            h = hashlib.new(hash)
            h.update(data)
            output = h.hexdigest()
        else:
            output = hash
        return output