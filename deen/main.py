import sys
import logging
import os.path
import argparse

from deen.loader import DeenPluginLoader

ICON = os.path.dirname(os.path.abspath(__file__)) + '/media/icon.png'
LOGGER = logging.getLogger()
VERBOSE_FORMAT = '[%(filename)s:%(lineno)s - %(funcName)20s() ] %(message)s'

ARGS = argparse.ArgumentParser(description='apply encodings, compression and hashing to arbitrary input data.')
ARGS.add_argument('infile', nargs='?', default=None,
                  help="file name or - for STDIN")
ARGS.add_argument('-l', '--list', action='store_true', dest='list',
                  default=False, help='list available plugins')
ARGS.add_argument('-p', '--plugin', action='store', dest='plugin',
                  metavar='PLUGIN', default=None, help='deen plugin to use')
ARGS.add_argument('-r', '--revert', action='store_true', dest='revert',
                  default=False, help='revert plugin process (e.g. decode or uncompress')
ARGS.add_argument('-d', '--data', action='store', dest='data',
                  default=None, help='instead of a file, provide an input string')
ARGS.add_argument('-n', action='store_true', dest='nonewline',
                  default=False, help='omit new line character at the end of the output')
ARGS.add_argument('-v', '--verbose', action='count', dest='level',
                  default=0, help='verbose logging (repeat for more verbosity)')

def main():
    args = ARGS.parse_args()
    pl = DeenPluginLoader()
    content = None
    if args.infile:
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
    elif args.data:
        content = bytearray(args.data, 'utf8')
    if any([args.list, args.plugin]):
        # We are in command line mode
        log_format = VERBOSE_FORMAT if args.level > 0 else '%(message)s'
        levels = [logging.WARN, logging.DEBUG]
        logging.basicConfig(level=levels[min(args.level, len(levels) - 1)], format=log_format)
        if args.list:
            print(pl.pprint_available_plugins())
            return
        if not content:
            LOGGER.error('Please provide a file or pipe into STDIN')
            sys.exit(1)
        try:
            # Python 3
            stdout = sys.stdout.buffer
        except AttributeError:
            # Python 2
            stdout = sys.stdout
        if not args.plugin:
            LOGGER.error('No plugin supplied')
            sys.exit(1)
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
        stdout.write(processed)
        if not args.nonewline:
            stdout.write(b'\n')
    else:
        # We are in GUI mode
        # Import GUI related modules only in GUI
        # mode to speed up CLI mode.
        from PyQt5.QtWidgets import QApplication
        from PyQt5.QtGui import QIcon
        from deen.widgets.core import Deen
        logging.basicConfig(format=VERBOSE_FORMAT)
        app = QApplication(sys.argv)
        ex = Deen()
        if content:
            # GUI mode also supports input files and
            # content via STDIN.
            ex.encoder_widget.set_root_content(content)
        ex.setWindowIcon(QIcon(ICON))
        LOGGER.addHandler(ex.log)
        return app.exec_()
