import logging
import pprint
import json
import xml.dom.minidom
from xml.parsers.expat import ExpatError

try:
    import jsbeautifier
except ImportError:
    JSBEAUTIFIER = False
else:
    JSBEAUTIFIER = True

LOGGER = logging.getLogger(__name__)


class XmlFormat(object):
    def __init__(self):
        self._content = None
        self._error = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        assert isinstance(data, (bytes, bytearray))
        try:
            parser = xml.dom.minidom.parseString(data)
        except ExpatError as e:
            self._error = e
            return
        document = parser.toprettyxml(indent=' ' * 4,
                                      encoding='utf8')
        self._content = bytearray(document)

    @property
    def error(self):
        return self._error


class HtmlFormat(object):
    def __init__(self):
        self._content = None
        self._error = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        assert isinstance(data, (bytes, bytearray))
        try:
            parser = xml.dom.minidom.parseString(data)
        except ExpatError as e:
            self._error = e
            return
        document = parser.toprettyxml(indent='  ',
                                      encoding='utf8')
        if document.startswith(b'<?xml version="1.0" encoding="utf8"?>\n') and \
                not data.startswith(b'<?xml version="1.0" encoding="utf8"?>'):
            index = document.index(b'\n')
            document = document[index+1:]
        self._content = bytearray(document)

    @property
    def error(self):
        return self._error


class JsonFormat(object):
    def __init__(self):
        self._content = None
        self._error = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        assert isinstance(data, (bytes, bytearray))
        try:
            data = json.loads(data.decode())
        except (json.JSONDecodeError, TypeError) as e:
            self._error = e
            return
        data = pprint.pformat(data)
        self._content = bytearray(data.encode())

    @property
    def error(self):
        return self._error


class JsBeautifierFormat(object):
    def __init__(self):
        self._content = None
        self._error = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        assert isinstance(data, (bytes, bytearray))
        if not JSBEAUTIFIER:
            LOGGER.warning('jsbeautifier is not available')
            return
        opts = jsbeautifier.default_options()
        opts.unescape_strings = True
        try:
            data = jsbeautifier.beautify(data.decode(), opts)
        except (UnicodeDecodeError, TypeError) as e:
            self._error = e
            return
        self._content = bytearray(data.encode())

    @property
    def error(self):
        return self._error