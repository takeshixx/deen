class DeenPlugin(object):
    """The core plugin class that should be subclassed
    by every deen plugin. It provides some required
    class attributes that ease the process of writing
    new plugins."""

    # In case an error happened, it should
    # be stored in this variable.
    error = None
    # Internal name for the plugin.
    name = ''
    # The name that will be displayed in the GUI.
    display_name = ''
    # A list of aliases for this plugin. Can
    # be empty if there is no aliases to the
    # plugin name.
    aliases = []

    def __init__(self):
        pass

    @staticmethod
    def prerequisites():
        """A function that should return True if all
        prerequisites for this plugin are met or False
        if not. Here a plugin can e.g. check if the
        current Python version is suitable for the
        functionality or if required third party modules
        are installed."""
        return True

    def process(self, data):
        """Every plugin must have a process method
        that e.g. encodes, compresses, hashs, formats,
        whatsoever."""
        assert data is not None
        assert isinstance(data, (bytes, bytearray))

    def unprocess(self, data):
        """Depending of the category of a plugin, it
        could also have an unprocess function. This
        applies to e.g. codecs and compressions.
        However, e.g. hash functions will not require
        an unprocess function as they are not (easily)
        reversible."""
        assert data is not None
        assert isinstance(data, (bytes, bytearray))