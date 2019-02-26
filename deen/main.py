import sys
import os.path
import argparse
import logging

from deen.loader import DeenPluginLoader
from deen import constants
from deen import logger

LOGGER = logger.DEEN_LOG


class DeenHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """This formatter is a hack for printing the default
    metavar for the plugin_cmd subparsers. It will prevent
    argparse from printing additional lists of all cmds."""
    def _metavar_formatter(self, action, default_metavar):
        if action.metavar is not None:
            result = action.metavar
        else:
            result = default_metavar

        def format_metavar(tuple_size):
            if isinstance(result, tuple):
                return result
            else:
                return (result, ) * tuple_size
        return format_metavar


ARGS = argparse.ArgumentParser(formatter_class=DeenHelpFormatter,
                               description=constants.cli_description,
                               epilog=constants.cli_epilog)
ARGS.add_argument('-f', '--file', dest='infile', default=None, metavar='filename',
                  help='file name or - for STDIN')
ARGS.add_argument('-l', '--list', action='store_true', dest='list',
                  default=False, help='list available plugins')
ARGS.add_argument('-p', '--plugin', action='store', dest='plugin',
                  metavar='plugin', default=None, help='deen plugin to use')
ARGS.add_argument('-r', '--revert', action='store_true', dest='revert',
                  default=False, help='revert plugin process (e.g. decode or uncompress)')
ARGS.add_argument('-d', '--data', action='store', dest='data', metavar='data',
                  default=None, help='instead of a file, provide an input string')
ARGS.add_argument('-n', '--no-new-line', action='store_true', dest='nonewline',
                  default=False, help='omit new line character at the end of the output')
ARGS.add_argument('--version', action='store_true', dest='version',
                  default=False, help='print the current version')
ARGS.add_argument('-v', '--verbose', action='count', dest='level',
                  default=0, help='verbose logging (repeat for more verbosity)')


def main():
    pl = DeenPluginLoader(argparser=ARGS)
    args = ARGS.parse_args()
    content = pl.read_content_from_args()
    levels = [logging.WARN, logging.DEBUG]
    LOGGER.setLevel(levels[min(args.level, len(levels) - 1)])
    if args.list:
        print('Loaded plugins:')
        print(pl.pprint_available_plugins())
        if pl.invalid_plugins:
            print('\nNot loaded plugins:')
            print(pl.pprint_invalid_plugins())
    elif args.version:
        print(constants.__version__)
    elif any([args.plugin_cmd, args.plugin]) and args.plugin_cmd != 'gui':
        # We are in command line mode
        if args.plugin_cmd:
            # Run subcommands
            if not pl.get_plugin_cmd_available(args.plugin_cmd):
                LOGGER.error('Plugin cmd not available')
                sys.exit(1)
            plugin = pl.get_plugin_cmd_name_instance(args.plugin_cmd)
            plugin.content = content
            processed = plugin.process_cli(args)
        else:
            # Use plugins via -p/--plugin
            if not pl.plugin_available(args.plugin):
                LOGGER.error('Plugin not available')
                sys.exit(1)
            plugin = pl.get_plugin_instance(args.plugin)
            if not args.revert:
                processed = plugin.process(content)
            else:
                unprocess_func = getattr(plugin, 'unprocess', None)
                if not unprocess_func or not callable(unprocess_func):
                    LOGGER.error('Plugin cannot unprocess data')
                    sys.exit(1)
                processed = plugin.unprocess(content)
        if plugin.error:
            sys.exit(1)
        if not processed:
            LOGGER.debug('Plugin {} did not return any data'.format(plugin.cmd_name))
            sys.exit(1)
        plugin.write_to_stdout(processed, nonewline=args.nonewline)
    else:
        # We are in GUI mode
        # Import GUI related modules only in GUI
        # mode to speed up CLI mode.
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtGui import QIcon
        from deen.gui.core import DeenGui
        app = QApplication(sys.argv)
        ex = DeenGui(plugins=pl)
        if content:
            # GUI mode also supports input files and
            # content via STDIN.
            ex.set_root_content(content)
        ex.setWindowIcon(QIcon(os.path.dirname(os.path.abspath(__file__)) +
                               constants.icon_path))
        LOGGER.addHandler(ex.log)
        if pl.invalid_plugins:
            LOGGER.warning('Not loaded plugins:\n' + pl.pprint_invalid_plugins())
            plugins = ', '.join([x[0][1].display_name for x in pl.invalid_plugins])
            message = 'Failed to load plugin(s), see status console '
            message += '(CTRL+P) for more information: ' + plugins
            ex.statusBar().showMessage(message, 5000)
        return app.exec_()
