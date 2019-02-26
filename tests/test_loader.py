import os
import sys
import unittest
import tempfile
import shutil
import importlib

from deen.loader import DeenPluginLoader
from deen.exceptions import *

test_plugin="""
from deen.plugins import DeenPlugin
class DeenPluginTestPlugin(DeenPlugin):
    name = 'base64'
    display_name = 'Base64'
    aliases = ['b64']
    cmd_name = 'base64'
    cmd_help = 'Base64 encode/decode data'

    def __init__(self):
        super(DeenPluginTestPlugin, self).__init__()

    @staticmethod
    def prerequisites():
        return True

    def process(self, data):
        super(DeenPluginTestPlugin, self).process(data)
        return data

    def unprocess(self, data):
        super(DeenPluginTestPlugin, self).unprocess(data)
        return data

    def process_cli(self, args):
        pass

    def process_gui(self):
        pass

    @staticmethod
    def add_argparser(argparser, *args):
        pass
"""


class TestDeenPluginLoader(unittest.TestCase):
    plugin_categories = ['codecs',
                         'compressions',
                         'assemblies',
                         'hashs',
                         'formatters',
                         'misc']

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.module_name = 'deentest_' + os.path.basename(self.temp_dir)
        # self.temp_dir will be added to sys.path
        # so that importing self.module_name is
        # possible in all submodules.
        sys.path.append(self.temp_dir)
        self._create_plugins()

    def tearDown(self):
        shutil.rmtree(self.temp_dir)

    def _create_plugins(self):
        plugins_path = self.temp_dir + '/' + self.module_name + '/plugins'
        for c in self.plugin_categories:
            os.makedirs(plugins_path + '/' + c)
        with open(plugins_path + '/codecs/plugin_base64.py', 'w') as f:
            f.write(test_plugin)

    def test_load_plugins(self):
        self.loader = DeenPluginLoader(base=self.module_name)


if __name__ == '__main__':
    unittest.main()