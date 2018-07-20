import sys
import inspect
import pkgutil
import importlib
import pprint
import logging

import deen.plugins.codecs
import deen.plugins.compressions
import deen.plugins.assemblies
import deen.plugins.hashs
import deen.plugins.formatters
import deen.plugins.misc

LOGGER = logging.getLogger()


class DeenPluginLoader(object):
    """Instances of this class can be used
    to load plugins in order to interact with
    them."""
    def __init__(self, argparser=None):
        self.codecs = []
        self.compressions = []
        self.assemblies = []
        self.hashs = []
        self.formatters = []
        self.misc = []
        self._argparser = None
        self._subargparser = None
        if argparser:
            self.argparser = argparser
        self.load_plugins()

    @property
    def argparser(self):
        return self._argparser

    @argparser.setter
    def argparser(self, argparser):
        self._argparser = argparser

    @property
    def available_plugins(self):
        """Returns a list of tuples of all available
        plugins in the plugin folder."""
        return self.codecs + self.compressions + \
                self.hashs + self.formatters + self.misc + \
                self.assemblies

    def pprint_available_plugins(self):
        """Returns a pprint.pformat representation
        of all available plugins. It will most likely
        be a human readable list."""
        pp = pprint.PrettyPrinter(indent=4)
        return pp.pformat([p[1].display_name for p in self.available_plugins])

    def _get_submodules_from_namespace_package(self, package):
        """An internal helper function that returns
        a list of submodules in the given namespace
        package."""
        output = []
        for module in  pkgutil.iter_modules(package.__path__, package.__name__ + '.'):
            output.append(module.name)
        return output

    def _get_plugin_classes_from_module(self, package):
        """An internal helper function that extracts
        all plugin classes from modules in the plugins
        folder."""
        output = []
        for m in self._get_submodules_from_namespace_package(package):
            module = importlib.import_module(m, package=None)
            for c in inspect.getmembers(module, inspect.isclass):
                # Only classes that start with DeenPlugin will be loaded.
                if c[0].startswith('DeenPlugin') and \
                        len(c[0].replace('DeenPlugin', '')) != 0:
                    # Call the prerequisites() function before loading plugin.
                    if c[1].prerequisites():
                        # Check if the plugin wants to add additional CLI arguments.
                        if self.argparser:
                            if getattr(c[1], 'cmd_name', None) and c[1].cmd_name and \
                                    getattr(c[1], 'cmd_help', None) and c[1].cmd_help:
                                add_argparser_func = getattr(c[1], 'add_argparser', None)
                                if not self._subargparser and self._argparser:
                                    self._subargparser = self._argparser.add_subparsers(dest='plugin_cmd')
                                add_argparser_func(self._subargparser, c[1].cmd_name,
                                                   c[1].cmd_help, c[1].aliases)
                        output.append(c)
                    else:
                        LOGGER.warning('Prerequisits for plugin {} not met'.format(c[0]))
        else:
            return output

    def load_plugins(self):
        """A generic function that fills the class lists
        with the available plugins. This function could
        also be called multiple times or at a later point
        in time to reload plugins."""
        self.codecs = self._get_plugin_classes_from_module(deen.plugins.codecs)
        self.compressions = self._get_plugin_classes_from_module(deen.plugins.compressions)
        self.assemblies = self._get_plugin_classes_from_module(deen.plugins.assemblies)
        self.hashs = self._get_plugin_classes_from_module(deen.plugins.hashs)
        self.formatters = self._get_plugin_classes_from_module(deen.plugins.formatters)
        self.misc = self._get_plugin_classes_from_module(deen.plugins.misc)

    def plugin_available(self, name):
        """Returns True if the given plugin name is available,
        False if not."""
        return True if self.get_plugin(name) else False

    def get_plugin_instance(self, name):
        """Returns an instance of the plugin for the
        given name. This will most likely be the
        function that should be called in order to
        use the plugins."""
        return self.get_plugin(name)()

    def get_plugin(self, name):
        """Returns the plugin module for the given name."""
        for plugin in self.available_plugins:
            if name == plugin[0] or name == plugin[1].name or \
                    name == plugin[1].display_name or name in plugin[1].aliases:
                return plugin[1]
        else:
            return None

    def get_plugin_cmd_available(self, name):
        """Returns True if the given plugin cmd is available,
        False if not."""
        return True if self.get_plugin_by_cmd_name(name) else False

    def get_plugin_cmd_name_instance(self, name):
        return self.get_plugin_by_cmd_name(name)()

    def get_plugin_by_cmd_name(self, name):
        """Returns the plugin module for the given cmd name."""
        for plugin in self.available_plugins:
            if not getattr(plugin[1], 'cmd_name', None) or \
                    not plugin[1].cmd_name:
                continue
            if name == plugin[1].cmd_name or \
                    name in plugin[1].aliases:
                if getattr(plugin[1], 'process_cli', None):
                    return plugin[1]
        else:
            return None

    def read_content_from_args(self):
        args = self.argparser.parse_args()
        content = None
        if getattr(args, 'infile', None) and args.infile:
            try:
                if args.infile == '-':
                    try:
                        stdin = sys.stdin.buffer
                    except AttributeError:
                        stdin = sys.stdin
                    content = stdin.read()
                else:
                    with open(args.infile, 'rb') as f:
                        content = f.read()
            except KeyboardInterrupt:
                return
        elif getattr(args, 'data', None) and args.data:
            content = bytearray(args.data, 'utf8')
        return content