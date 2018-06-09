import sys
import logging
import os.path
import argparse

from deen.loader import DeenPluginLoader

ICON = os.path.dirname(os.path.abspath(__file__)) + '/media/icon.png'
LOGGER = logging.getLogger()
VERBOSE_FORMAT = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s'
EPILOG = """examples:
  open a file in the deen GUI:
    $ deen /bin/ls
    
  open file from STDIN in deen GUI:
    $ cat /bin/ls | deen -
    
  base64 encode a string:
    $ deen -b base64 -d admin:admin
    YWRtaW46YWRtaW4=

  base64 encode a string with subcommand:
    $ deen base64 admin:admin
    YWRtaW46YWRtaW4=
    
  decode Base64 string:
    $ deen -b base64 -r -d YWRtaW46YWRtaW4=
    admin:admin
    
  decode Base64 string with subcommand:
    $ deen base64 -r YWRtaW46YWRtaW4=
    admin:admin
    
  calculate the SHA256 hash of file:
    $ deen sha256 /bin/ls
    df285ab34ad10d8b641e65f39fa11a7d5b44571a37f94314debbfe7233021755
"""

ARGS = argparse.ArgumentParser(description='apply encodings, compression and hashing to arbitrary input data.',
                               formatter_class=argparse.RawDescriptionHelpFormatter, epilog=EPILOG)
ARGS.add_argument('-f', '--file', dest='infile', default=None,
                  help='file name or - for STDIN')
ARGS.add_argument('-l', '--list', action='store_true', dest='list',
                  default=False, help='list available plugins')
ARGS.add_argument('-p', '--plugin', action='store', dest='plugin',
                  metavar='PLUGIN', default=None, help='deen plugin to use')
ARGS.add_argument('-r', '--revert', action='store_true', dest='revert',
                  default=False, help='revert plugin process (e.g. decode or uncompress')
ARGS.add_argument('-d', '--data', action='store', dest='data',
                  default=None, help='instead of a file, provide an input string')
ARGS.add_argument('-n', '--no-new-line', action='store_true', dest='nonewline',
                  default=False, help='omit new line character at the end of the output')
ARGS.add_argument('-v', '--verbose', action='count', dest='level',
                  default=0, help='verbose logging (repeat for more verbosity)')


def main():
    pl = DeenPluginLoader(argparser=ARGS)
    args = ARGS.parse_args()
    content = pl.read_content_from_args()
    if args.list:
        print(pl.pprint_available_plugins())
    elif any([args.plugin_cmd, args.plugin]):
        # We are in command line mode
        log_format = VERBOSE_FORMAT if args.level > 0 else '%(message)s'
        levels = [logging.WARN, logging.DEBUG]
        logging.basicConfig(level=levels[min(args.level, len(levels) - 1)], format=log_format)
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
        if not processed:
            if plugin.error:
                LOGGER.error(plugin.error)
            else:
                LOGGER.error('Plugin {} did not return any data'.format(plugin.cmd_name))
            sys.exit(1)
        plugin.write_to_stdout(processed)
    else:
        # We are in GUI mode
        # Import GUI related modules only in GUI
        # mode to speed up CLI mode.
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtGui import QIcon
        from deen.gui.core import DeenGui
        logging.basicConfig(format=VERBOSE_FORMAT)
        app = QApplication(sys.argv)
        ex = DeenGui(plugins=pl)
        if content:
            # GUI mode also supports input files and
            # content via STDIN.
            ex.set_root_content(content)
        ex.setWindowIcon(QIcon(ICON))
        LOGGER.addHandler(ex.log)
        return app.exec_()
