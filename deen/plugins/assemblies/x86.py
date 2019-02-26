try:
    import keystone
except ImportError:
    keystone = None
try:
    import capstone
except ImportError:
    capstone = None

from .__base__ import AsmBase


class DeenPluginAsmX86(AsmBase):
    name = 'assembly_x86'
    display_name = 'x86'
    aliases = ['asm_x86',
               'asmx86',
               'assemble_x86',
               'assemblex86',
               'x86']
    cmd_name = 'assembly_x86'
    cmd_help='Assemble/Disassemble for the x86 architecture'
    keystone_arch = keystone.KS_ARCH_X86 \
        if (keystone and hasattr(keystone, 'KS_ARCH_X86')) else None
    keystone_mode = keystone.KS_MODE_32 \
        if (keystone and hasattr(keystone, 'KS_MODE_32')) else None
    capstone_arch = capstone.CS_ARCH_X86 \
        if (capstone and hasattr(capstone, 'CS_ARCH_X86')) else None
    capstone_mode = capstone.CS_MODE_32 \
        if (capstone and hasattr(capstone, 'CS_MODE_32')) else None

    def __init__(self, atandt=False):
        super(DeenPluginAsmX86, self).__init__()
        if keystone and capstone:
            self.set_syntax(atandt)

    def reinitialize(self):
        if self.args and getattr(self.args, 'atandt', None) \
                and self.args.atandt:
            self.set_syntax(self.args.atandt)

    def set_syntax(self, atandt=False):
        if atandt:
            self.ks.syntax = keystone.KS_OPT_SYNTAX_ATT
            self.cs.syntax = capstone.CS_OPT_SYNTAX_ATT
        else:
            self.ks.syntax = keystone.KS_OPT_SYNTAX_INTEL
            self.cs.syntax = capstone.CS_OPT_SYNTAX_INTEL

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None,
                      *args, **kwargs):
        # Add an additional argument for AT&T syntax.
        parser = AsmBase.add_argparser(argparser, cmd_name,
                                       cmd_help, cmd_aliases=cmd_aliases)
        parser.add_argument('-a', '--atandt', dest='atandt',
                            default=False, help='use AT&T syntax',
                            action='store_true')

    def _syntax_highlighting(self, data):
        try:
            from pygments import highlight
            from pygments.lexers import NasmLexer, GasLexer
            from pygments.formatters import TerminalFormatter, Terminal256Formatter
            from pygments.styles import get_style_by_name
            style = get_style_by_name('colorful')
            import curses
            curses.setupterm()
            if curses.tigetnum('colors') >= 256:
                FORMATTER = Terminal256Formatter(style=style)
            else:
                FORMATTER = TerminalFormatter()
            if self.ks.syntax == keystone.KS_OPT_SYNTAX_INTEL:
                lexer = NasmLexer()
            else:
                lexer = GasLexer()
            # When pygments is available, we
            # can print the disassembled
            # instructions with syntax
            # highlighting.
            data = highlight(data, lexer, FORMATTER)
        except ImportError:
            pass
        finally:
            data = data.encode()
        return data


class DeenPluginAsmX86_64(DeenPluginAsmX86):
    name = 'assembly_x86_64'
    display_name = 'x86_64'
    aliases = ['asm_x86_64',
               'asmx86_64',
               'x86_64',
               'x64']
    cmd_name = 'assembly_x86_64'
    cmd_help='Assemble/Disassemble for the x86_64 architecture'
    keystone_arch = keystone.KS_ARCH_X86 \
        if (keystone and hasattr(keystone, 'KS_ARCH_X86')) else None
    keystone_mode = keystone.KS_MODE_64 \
        if (keystone and hasattr(keystone, 'KS_MODE_64')) else None
    capstone_arch = capstone.CS_ARCH_X86 \
        if (capstone and hasattr(capstone, 'CS_ARCH_X86')) else None
    capstone_mode = capstone.CS_MODE_64 \
        if (capstone and hasattr(capstone, 'CS_MODE_64')) else None
