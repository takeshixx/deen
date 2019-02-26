import sys

import deen.logger


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
        self.parent = None
        self.content = None
        self.log = None
        self._content = bytearray()
        self._create_log_handler()

    @property
    def content(self):
        return self._content

    @content.setter
    def content(self, data):
        if isinstance(data, str):
            data = data.encode()
        if isinstance(data, bytes):
            data = bytearray(data)
        self._content = data

    def prerequisites(self):
        """A function that should return True if all
        prerequisites for this plugin are met or False
        if not. Here a plugin can e.g. check if the
        current Python version is suitable for the
        functionality or if required third party modules
        are installed.

        :return: True if all prerequisites are met,
                 False if not.
        """
        return True

    def process(self, data):
        """Every plugin must have a process method
        that e.g. encodes, compresses, hashs, formats,
        whatsoever.

        :param data: the input data that should be
                     processed
        :return: the processed data
        """
        assert data is not None,\
            'Input data is None'
        assert isinstance(data, (bytes, bytearray)),\
            'Invalid input type: ' + str(type(data))

    def unprocess(self, data):
        """Depending of the category of a plugin, it
        could also have an unprocess function. This
        applies to e.g. codecs and compressions.
        However, e.g. hash functions will not require
        an unprocess function as they are not (easily)
        reversible.

        :param data: the input data that should be
                     processed
        :return: the processed data
        """
        assert data is not None,\
            'Input data is None'
        assert isinstance(data, (bytes, bytearray)),\
            'Invalid input type: ' + str(type(data))

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None,
                      revert=True):
        """This function allows plugins to add subcommands
        to argparse in order to be used via a seperate
        command/alias on the CLI.

        :param argparser: a ArgParser object
        :param cmd_name: a plugin's cmd_name class variable
        :param cmd_help: a plugin's cmd_help class variable
        :param cmd_aliases: a plugin's cmd_aliases class variable
        :param revert: True will add the -r/--revert argument
        :return: the newly created argparse object
        """
        if not cmd_aliases:
            cmd_aliases = []
        # Note: Python 2 argparse does not support aliases.
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(cmd_name, help=cmd_help, description=cmd_help)
        else:
            parser = argparser.add_parser(cmd_name, help=cmd_help, aliases=cmd_aliases,
                                          description=cmd_help)
        parser.add_argument('plugindata', action='store',
                            help='input data', nargs='?')
        parser.add_argument('-f', '--file', dest='plugininfile', default=None,
                            help='file name or - for STDIN', metavar='filename')
        if revert:
            parser.add_argument('-r', '--revert', action='store_true', dest='revert',
                                default=False, help='revert plugin process')

    def process_cli(self, args):
        """Do whatever the CLI cmd should do. The args
        argument is the return of parse_args(). Must
        return the processed data.

        :param args: the output of argparse.parse_args()
        :return: the return of either process() or unprocess()
        """
        if not self.content:
            if not args.plugindata:
                if not args.plugininfile:
                    self.content = self.read_content_from_file('-')
                else:
                    self.content = self.read_content_from_file(args.plugininfile)
            else:
                self.content = args.plugindata
        if not self.content:
            return
        if not args.revert:
            return self.process(self.content)
        else:
            return self.unprocess(self.content)

    def process_gui(self, parent, content):
        """Plugins that need additional GUI elements
        i.e. to accept multiple inputs, they can
        override this function. The parent argument
        can be used to add widgets to the main window.

        :param parent: the parent object
        :param content: the input data that will be processed
        :return: the return value of process()
        """
        self.parent = parent

    def unprocess_gui(self, parent, content):
        """Plugins that need additional GUI elements
        i.e. to accept multiple inputs, they can
        override this function. The parent argument
        can be used to add widgets to the main window.

        :param parent: the parent object
        :param content: the input data that will be processed
        :return: the return value of unprocess()
        """
        self.parent = parent
        self.content = content

    def read_content_from_file(self, file):
        """If file is a filename, it will read and
        return it's content. If file is '-', read
        from STDIN instead of a file.

        :param file: filename of '-' for STDIN
        :return: content of filename or data from STDIN
        """
        content = b''
        try:
            if file == '-':
                try:
                    stdin = sys.stdin.buffer
                except AttributeError:
                    stdin = sys.stdin
                content = stdin.read()
            else:
                try:
                    with open(file, 'rb') as f:
                        content = f.read()
                except Exception as e:
                    self.error = e
        except KeyboardInterrupt:
            return
        return content

    def write_to_stdout(self, data, nonewline=False):
        """Write processed data to STDOUT. It takes
        care of whether it's running in Pyton 2 or 3
        to properly write bytes to STDOUT.

        :param data: data to be written to STDOUT
        :param nonewline: if True, omit newline at the end
        """
        try:
            # Python 3
            stdout = sys.stdout.buffer
        except AttributeError:
            # Python 2
            stdout = sys.stdout
        stdout.write(data)
        if not nonewline:
            stdout.write(b'\n')

    def _create_log_handler(self):
        """Create a log handler for each plugin instance.
        Plugins are supposed to log via self.log, i.e.
        self.log.info()."""
        logger = 'plugins.' + self.__class__.__name__
        self.log = deen.logger.DEEN_LOG.getChild(logger)

    def log_missing_depdendencies(self, dep):
        """A helper function for plugins
        to log missing dependencies in the
        self.prerequisites() function.

        :param dep: a str or list of module names"""
        if isinstance(dep, list):
            dep = ','.join(dep)
            msg = dep
            msg += ' modules '
        else:
            msg = dep
            msg += ' module '
        msg += 'not found, '
        msg += self.display_name
        msg += ' plugin disabled.'
        self.log.debug(msg)

    def log_incompatible_version(self, version=''):
        """A helper function for plugins to log
        missing features in current Python version.

        :param version: a str with a Python version (optional)"""
        msg = 'Python version ' + str(sys.version_info.major)
        msg += '.' + str(sys.version_info.minor)
        msg += ' does not support ' + self.display_name
        if version:
            msg += ' (v' + version
            msg += ' required)'
        self.log.debug(msg)
