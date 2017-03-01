import os
import unittest
import random
import string

from deen.transformers.core import DeenTransformer
from deen.transformers.formats import XmlFormat, HtmlFormat, JsonFormat


class TestFormatters(unittest.TestCase):
    def setUp(self):
        self._transformer = DeenTransformer()

    def _random_str(self, length=16):
        return ''.join(random.choice(string.ascii_uppercase + string.digits)
                for _ in range(length))

    def _random_bytes(self, length=16):
        return os.urandom(length)

    def test_format_xml(self):
        doc = (b'<?xml version="1.0" encoding="UTF-8"?><note>'
               b'<to>Tove</to><from>Jani</from><heading>Reminder'
               b'</heading><body>Don\'t forget me this weekend!'
               b'</body></note>')
        formatter = XmlFormat()
        try:
            formatter.content = doc
        except Exception as e:
            self.fail(e)

    def test_format_xml_invalid(self):
        doc = (b'<?xml version="1.0" encoding="UTF-8"?><note>'
               b'<to>Tove</ERRORto><from>Jani</from><headingReminder'
               b'</heading><body>Don\'t forget me this weekend!'
               b'</bodyXXX></note>')
        formatter = XmlFormat()
        try:
            formatter.content = doc
        except Exception as e:
            self.fail(e)

    def test_format_html(self):
        doc = (b'<!DOCTYPE html><html><body><h1>My First Heading'
               b'</h1><p>My first paragraph.</p></body></html>')
        formatter = HtmlFormat()
        try:
            formatter.content = doc
        except Exception as e:
            self.fail(e)

    def test_format_html_invalid(self):
        doc = (b'<!DOCTYPE html><html><div><h1>My First Heading'
               b'</h1><p>My first paragraph.</p</body></html>')
        formatter = HtmlFormat()
        try:
            formatter.content = doc
        except Exception as e:
            self.fail(e)

    def test_format_json(self):
        doc = (b'{"employees":[{"firstName":"John", "lastName":'
               b'"Doe"},{"firstName":"Anna", "lastName":"Smith"}'
               b',{"firstName":"Peter", "lastName":"Jones"}]}')
        formatter = JsonFormat()
        try:
            formatter.content = doc
        except Exception as e:
            self.fail(e)

    def test_format_json_invalid(self):
        doc = (b'{"employees":[{{"firstName":"John", "lastName":'
               b'"Doe"},{"firstName":"Anna", "lastName""Smith"}'
               b',{"firstName":"Peter, "lastName":"Jones"}]}')
        formatter = JsonFormat()
        try:
            formatter.content = doc
        except Exception as e:
            self.fail(e)


if __name__ == '__main__':
    unittest.main()
