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

    def process(self, data):
        assert data is not None
        assert isinstance(data, (bytes, bytearray))

    def unprocess(self, data):
        assert data is not None
        assert isinstance(data, (bytes, bytearray))