"""The GUI part is not properly implemented yet.
The GUI is currently not able to set HTML-formatted
content that will be handled correctly in subsequent
encoder widgets. Adding HTML-formatted content
will currently alter the actual data, which will
influence all subsequent encoder widget results."""
from __future__ import absolute_import
import sys
try:
    import pygments
    import pygments.lexers
    import pygments.formatters
    import pygments.styles
    PYGMENTS = True
except ImportError:
    PYGMENTS = False

from PyQt5.QtWidgets import QDialog

from deen.exceptions import *
from .. import DeenPlugin

from deen.gui.widgets.ui_deenpluginsyntaxhighlighter import Ui_SyntaxHighlighterGui


class DeenPluginSyntaxHighlighter(DeenPlugin):
    name = 'syntax_highlighter'
    display_name = 'Syntax Highlight (f)'
    aliases = ['highlight',
               'syntax']
    cmd_name = 'syntax-highlight'
    cmd_help = 'Reformat HTML data'

    def __init__(self):
        super(DeenPluginSyntaxHighlighter, self).__init__()
        self.parent = None
        self.highlightergui = None

    def prerequisites(self):
        try:
            import pygments
        except ImportError:
            self.log_missing_depdendencies('pygments')
            return False
        else:
            return True

    def process(self, data, lexer=None, formatter=None):
        super(DeenPluginSyntaxHighlighter, self).process(data)
        if not lexer:
            lexer = pygments.lexers.TextLexer()
        if not formatter:
            formatter = pygments.formatters.NullFormatter()
        data = pygments.highlight(data, lexer, formatter)
        if not isinstance(data, (bytes, bytearray)):
            data = data.encode()
        return data


    @staticmethod
    def add_argparser(argparser, *args, **kwargs):
        # Python 2 argparse does not support aliases
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(DeenPluginSyntaxHighlighter.cmd_name,
                                          help=DeenPluginSyntaxHighlighter.cmd_help)
        else:
            parser = argparser.add_parser(DeenPluginSyntaxHighlighter.cmd_name,
                                          help=DeenPluginSyntaxHighlighter.cmd_help,
                                          aliases=DeenPluginSyntaxHighlighter.aliases)
        parser.add_argument('plugindata', action='store', help='input data', nargs='?')
        parser.add_argument('--list', action='store_true', dest='list',
                            default=False, help='list available lexers')
        parser.add_argument('--list-formatters', action='store_true', dest='listformatters',
                            default=False, help='list available formatters')
        parser.add_argument('-f', '--file', dest='plugininfile', default=None,
                            help='file name or - for STDIN', metavar='filename')
        parser.add_argument('--formatter', help='formatter to use',
                            type=str.lower, default=None, metavar='formatter')
        parser.add_argument('-l', '--lexer', help='hash algorithm for signature', default=None,
                            type=str.lower, metavar='lexer')
        parser.add_argument('-n', '--numbers', action='store_true', dest='numbers',
                            default=False, help='print line numbers')

    def process_cli(self, args):
        if not PYGMENTS:
            self.error = MissingDependencyException('pygments is not available')
            return
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
        style = pygments.styles.get_style_by_name('colorful')
        if args.lexer:
            lexer = pygments.lexers.get_lexer_by_name(args.lexer)
        else:
            lexer = pygments.lexers.guess_lexer(self.content.decode())
        if args.formatter:
            self.log.info('Guessing formatter')
            formatter = pygments.formatters.get_formatter_by_name(args.formatter)
        else:
            import curses
            curses.setupterm()
            if curses.tigetnum('colors') >= 256:
                formatter = pygments.formatters.Terminal256Formatter(style=style, linenos=args.numbers)
            else:
                formatter = pygments.formatters.TerminalFormatter(linenos=args.numbers)
        return self.process(self.content, lexer=lexer, formatter=formatter)

    def process_gui(self, parent, content):
        self.parent = parent
        self.highlightergui = SyntaxHighlighterGui(self.parent)
        for lexer in pygments.lexers.get_all_lexers():
            self.highlightergui.ui.lexer_combo.addItem(lexer[0])
        for formatter in pygments.formatters.get_all_formatters():
            self.highlightergui.ui.formatter_combo.addItem(formatter.name)
        if self.highlightergui.exec_() == 0:
            # If the plugin GUI is cancelled, just
            # return without doing anything.
            return
        lexer = self.highlightergui.ui.lexer_combo.currentText()
        for l in pygments.lexers.get_all_lexers():
            if lexer == l[0]:
                try:
                    lexer = l[1][0]
                except Exception:
                    continue
                else:
                    break
        else:
            self.log.error('Could not find lexer alias for ' + str(lexer))
            return
        lexer = pygments.lexers.get_lexer_by_name(lexer)
        if not lexer:
            self.log.error('Lexer not found: ' + str(lexer))
            return
        formatter = self.highlightergui.ui.formatter_combo.currentText()
        for f in pygments.formatters.get_all_formatters():
            if formatter == f.name:
                formatter = f.aliases[0]
                break
        else:
            self.log.error('Could not find formatter alias for ' + str(formatter))
            return
        formatter = pygments.formatters.get_formatter_by_name(formatter)
        if not formatter:
            self.log.error('Formatter not found: ' + str(formatter))
            return
        content = self.process(content, lexer=lexer, formatter=formatter)
        return content


class SyntaxHighlighterGui(QDialog):
    def __init__(self, parent):
        super(SyntaxHighlighterGui, self).__init__(parent)
        self.ui = Ui_SyntaxHighlighterGui()
        self.ui.setupUi(self)
        self.parent = parent
