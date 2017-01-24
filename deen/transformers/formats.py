import logging
import json
import pprint
try:
    import lxml.html
    import lxml.etree
    LXML = True
except ImportError:
    LXML = False

LOGGER = logging.getLogger(__name__)


class HtmlFormat(object):
    def __init__(self):
        self._content = None

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        if not LXML:
            return
        assert isinstance(data, (bytes, bytearray))
        document = lxml.html.fromstring(data.decode())
        document = lxml.etree.tostring(document,
                                       encoding='utf8',
                                       pretty_print=True)
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
