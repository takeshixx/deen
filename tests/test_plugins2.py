import os
import unittest
import random
import string

from deen.loader import DeenPluginLoader


class TestDeenPlugins(unittest.TestCase):
    plugin_categories = ['codecs',
                         'compressions',
                         'assemblies',
                         'hashs',
                         'formatters',
                         'misc']

    def setUp(self):
        self.loader = DeenPluginLoader()

    def _random_str(self, length=16):
        return ''.join(random.choice(string.ascii_uppercase + string.digits)
                for _ in range(length))

    def _random_bytes(self, length=16):
        return os.urandom(length)

    def _get_list_of_all_plugins(self):
        """Return a list of tuples of all loaded
        plugins. This function can be used to get
        an iterable to call functions of all
        plugins."""
        output = []
        for category in self.plugin_categories:
            plugins = getattr(self.loader, category)
            for plugin in plugins:
                output.append(plugin)
        return output

    def _all_plugins_call_func(self, func_name, data):
        """Call the process() function on all loaded
        plugins."""
        for plugin_name, plugin_class in self._get_list_of_all_plugins():
            if not func_name in vars(plugin_class):
                # Check if the class itself
                # implements the func()
                # function to ignore plugins
                # that inherit it from DeenPlugin.
                continue
            pname = plugin_name + '.' + func_name + '()'
            plugin = plugin_class()
            func = getattr(plugin, func_name)
            if not func:
                # Could not get the function.
                # This should never happen...
                continue
            try:
                processed = func(data)
            except AssertionError as e:
                # AssertionErrors can be ignored
                # as they are kind of supposed to
                # happen.
                print('AssertionError in ' + pname + ': ' + str(e))
                continue
            except Exception as e:
                # Plugins should always handle exceptions.
                self.fail('Unhandled exception in ' + pname + ': ' + str(e))
            else:
                if not processed:
                    # If the plugin did not return anything,
                    # check whether an expected error happened.
                    msg = pname + ' failed without setting plugin.error'
                    self.assertIsNotNone(plugin.error, msg)

    def test_process_bytes(self):
        data = self._random_bytes(256)
        self._all_plugins_call_func('process', data)

    def test_process_str(self):
        data = self._random_str(256)
        self._all_plugins_call_func('process', data)

    def test_unprocess_bytes(self):
        data = self._random_bytes(256)
        self._all_plugins_call_func('unprocess', data)

    def test_unprocess_str(self):
        data = self._random_str(256)
        self._all_plugins_call_func('unprocess', data)

    def test_process_unprocess_bytes(self):
        data = self._random_bytes(256)
        for category in ['codecs', 'compressions']:
            plugins = getattr(self.loader, category)
            for plugin_name, plugin_class in plugins:
                plugin = plugin_class()
                try:
                    processed = plugin.process(data)
                except AssertionError:
                    continue
                unprocessed = plugin.unprocess(processed)
                msg = plugin_name + ' process-unprocessed failed'
                self.assertEqual(data, unprocessed, msg)

    def test_process_unprocess_bytearray(self):
        data = bytearray(self._random_bytes(256))
        for category in ['codecs', 'compressions']:
            plugins = getattr(self.loader, category)
            for plugin_name, plugin_class in plugins:
                plugin = plugin_class()
                try:
                    processed = plugin.process(data)
                except AssertionError:
                    continue
                unprocessed = plugin.unprocess(processed)
                msg = plugin_name + ' process-unprocessed failed'
                self.assertEqual(data, unprocessed, msg)


if __name__ == '__main__':
    unittest.main()
