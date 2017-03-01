import logging
import pprint
import json
import xml.dom.minidom
from xml.parsers.expat import ExpatError

LOGGER = logging.getLogger(__name__)


class XmlFormat(object):
    def __init__(self):
        self._content = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        assert isinstance(data, (bytes, bytearray))
        try:
            parser = xml.dom.minidom.parseString(data)
        except ExpatError:
            return
        document = parser.toprettyxml(indent='  ',
                                      encoding='utf8')
        self._content = bytearray(document)


class HtmlFormat(object):
    def __init__(self):
        self._content = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        assert isinstance(data, (bytes, bytearray))
        try:
            parser = xml.dom.minidom.parseString(data)
        except ExpatError:
            return
        document = parser.toprettyxml(indent='  ',
                                      encoding='utf8')
        if document.startswith(b'<?xml version="1.0" encoding="utf8"?>\n') and \
                not data.startswith(b'<?xml version="1.0" encoding="utf8"?>'):
            index = document.index(b'\n')
            document = document[index+1:]
        self._content = bytearray(document)


class JsonFormat(object):
    def __init__(self):
        self._content = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        assert isinstance(data, (bytes, bytearray))
        try:
            data = json.loads(data)
        except json.JSONDecodeError as e:
            LOGGER.error(e)
            return
        data = pprint.pformat(data)
        self._content = bytearray(data.encode())
