import inspect
import pprint

import deen.plugins.codecs
import deen.plugins.compressions
import deen.plugins.hashs
import deen.plugins.formatters
import deen.plugins.misc


class DeenPluginLoader(object):
    """Instances of this class can be used
    to load plugins in order to interact with
    them."""
    def __init__(self):
        self.codecs = []
        self.compressions = []
        self.hashs = []
        self.formatters = []
        self.misc = []
        self.load_plugins()

    @property
    def available_plugins(self):
        """Returns a list of tuples of all available
        plugins in the plugin folder."""
        return self.codecs + self.compressions + \
                self.hashs + self.formatters + self.misc

    def pprint_available_plugins(self):
        """Returns a pprint.pformat representation
        of all available plugins. It will most likely
        be a human readable list."""
        pp = pprint.PrettyPrinter(indent=4)
        return pp.pformat([p[1].display_name for p in self.available_plugins])

    def _get_plugin_classes_from_module(self, module):
        """An internal helper function that extracts
        all plugin classes from modules in the plugins
        folder."""
        output = []
        for m in inspect.getmembers(module, inspect.ismodule):
            for c in inspect.getmembers(m[1], inspect.isclass):
                if c[0].startswith('DeenPlugin') and \
                        len(c[0].replace('DeenPlugin', '')) != 0:
                    output.append(c)
        else:
            return output

    def load_plugins(self):
        """A generic function that fills the class lists
        with the available plugins. This function could
        also be called multiple times or at a later point
        in time to reload plugins."""
        self.codecs = self._get_plugin_classes_from_module(deen.plugins.codecs)
        self.compressions = self._get_plugin_classes_from_module(deen.plugins.compressions)
        self.hashs = self._get_plugin_classes_from_module(deen.plugins.hashs)
        self.formatters = self._get_plugin_classes_from_module(deen.plugins.formatters)
        self.misc = self._get_plugin_classes_from_module(deen.plugins.misc)

    def plugin_available(self, name):
        """Returns True if the given plugin name is available,
        False if not."""
        return True if self.get_plugin(name) else False

    def get_plugin(self, name):
        """Returns the plugin module for the given name."""
        for plugin in self.available_plugins:
            if name == plugin[0] or name == plugin[1].name or \
                    name == plugin[1].display_name or name in plugin[1].aliases:
                return plugin[1]
        else:
            return None

    def get_plugin_instance(self, name):
        """Returns an instance of the plugin for the
        given name. This will most likely be the
        function that should be called in order to
        use the plugins."""
        return self.get_plugin(name)()