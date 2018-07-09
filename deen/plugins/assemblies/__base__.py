"""This file contains a base class for all assembly
plugins that are based on the Keystone and Capstone
engines. All of these plugins should be a child of
this class in order to provide the same base set of
features."""
import sys
import codecs
try:
    import keystone
    import capstone
    KEYSTONE = True
except ImportError:
    KEYSTONE = False

from .. import DeenPlugin


class AsmBase(DeenPlugin):
    # Each child class is responsible
    # for setting the followong class
    # variables with the appropriate
    # architectures and modes.
    keystone_arch = None
    keystone_mode = None
    capstone_arch = None
    capstone_mode = None
    ks = None
    cs = None

    def __init__(self):
        super(AsmBase, self).__init__()
        # Initialize keystone and capstone as soon as an instance
        # of this plugin will be created.
        if getattr(self, 'args', None) and self.args and getattr(self.args, 'bigendian', None) \
                and self.args.bigendian:
            self.ks = keystone.Ks(self.keystone_arch,
                                  self.keystone_mode + keystone.KS_MODE_BIG_ENDIAN)
            self.cs = capstone.Cs(self.capstone_arch,
                                  capstone.CS_MODE_BIG_ENDIAN)
        else:
            self.ks = keystone.Ks(self.keystone_arch,
                                  self.keystone_mode + keystone.KS_MODE_LITTLE_ENDIAN)
            self.cs = capstone.Cs(self.capstone_arch,
                                  capstone.CS_MODE_LITTLE_ENDIAN)

    @staticmethod
    def prerequisites():
        try:
            import keystone
            import capstone
        except ImportError:
            return False
        else:
            return True

    def process(self, data):
        super(AsmBase, self).process(data)
        try:
            encoding, count = self.ks.asm(data.decode())
        except keystone.KsError as e:
            self.error = e
            return b''
        return bytearray(encoding)

    def unprocess(self, data):
        super(AsmBase, self).unprocess(data)
        output = ''
        try:
            for (address, size, mnemonic, op_str) in self.cs.disasm_lite(bytes(data), 0x1000):
                if len(output) > 0:
                    output += '\n'
                output += '0x%x:\t%s\t%s' % (address, mnemonic, op_str)
        except capstone.CsError as e:
            self.error = e
            return b''
        return output.encode()

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None):
        if not cmd_aliases:
            cmd_aliases = []
        # Python 2 argparse does not support aliases
        if sys.version_info.major < 3 or \
            (sys.version_info.major == 3 and
                sys.version_info.minor < 2):
            parser = argparser.add_parser(cmd_name, help=cmd_help)
        else:
            parser = argparser.add_parser(cmd_name, help=cmd_help, aliases=cmd_aliases)
        parser.add_argument('plugindata', action='store', help='input data', nargs='?')
        parser.add_argument('-r', '--revert', action='store_true', dest='revert',
                            default=False, help='revert plugin process')
        parser.add_argument('-f', '--file', dest='plugininfile', default=None,
                            help='file name or - for STDIN', metavar='filename')
        parser.add_argument('-i', '--interactive', dest='interactive', default=False,
                            help='Interactive mode', action='store_true')
        parser.add_argument('--raw', dest='raw', default=False,
                            help='output raw bytes', action='store_true')

    def process_cli(self, args):
        # We should keep the args object so that
        # functions like _interactive_assembly()
        # can access CLI arguments.
        self.args = args
        if args.interactive:
            self._interactive_assembly()
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
        if args.revert:
            return self.unprocess(self.content)
        else:
            return self.process(self.content)

    def _interactive_assembly(self):
        # Import readline module to make arrow keys
        # and command history work in the interactive
        # mode.
        import readline
        try:
            from pygments import highlight
            from pygments.lexers import NasmLexer
            from pygments.formatters import TerminalFormatter, Terminal256Formatter
            from pygments.styles import get_style_by_name
            PYGMENTS = True
            style = get_style_by_name('colorful')
            import curses
            curses.setupterm()
            if curses.tigetnum('colors') >= 256:
                FORMATTER = Terminal256Formatter(style=style)
            else:
                FORMATTER = TerminalFormatter()
        except ImportError:
            PYGMENTS = False
            FORMATTER = False
        while True:
            try:
                data = input('> ')
                if not data:
                    continue
                try:
                    if self.args.revert:
                        try:
                            data = codecs.decode(data, 'hex')
                        except Exception:
                            self.write_to_stdout(b'Invalid hex encoding')
                            continue
                        output = self.unprocess(data)
                        # When pygments is available, we
                        # can print the disassembled
                        # instructions with syntax
                        # highlighting.
                        if all([PYGMENTS, FORMATTER]):
                            try:
                                output = highlight(output, NasmLexer(), FORMATTER)
                            except Exception:
                                # When pygment failes, just
                                # continue printing the raw
                                # output.
                                pass
                            finally:
                                output = output.encode()
                    else:
                        encoding, count = self.ks.asm(data)
                        if self.args.raw:
                            output = bytes(bytearray(encoding))
                        else:
                            output = codecs.encode(bytearray(encoding), 'hex')
                    self.write_to_stdout(output)
                except keystone.KsError as e:
                    self.write_to_stdout(str(e).encode())
            except (KeyboardInterrupt, EOFError):
                return b''
