import os
import unittest
import random
import string

from deen.loader import DeenPluginLoader


class TestFormatters(unittest.TestCase):
    def setUp(self):
        self._plugins = DeenPluginLoader()

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
