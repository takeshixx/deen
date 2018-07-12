try:
    import keystone
    import capstone
    KEYSTONE = True
except ImportError:
    KEYSTONE = False

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
    keystone_arch = keystone.KS_ARCH_X86 if KEYSTONE else None
    keystone_mode = keystone.KS_MODE_32 if KEYSTONE else None
    capstone_arch = capstone.CS_ARCH_X86 if KEYSTONE else None
    capstone_mode = capstone.CS_MODE_32 if KEYSTONE else None

    def _syntax_highlighting(self, data):
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
            # When pygments is available, we
            # can print the disassembled
            # instructions with syntax
            # highlighting.
            data = highlight(data, NasmLexer(), FORMATTER)
        except ImportError:
            pass
        finally:
            data = data.encode()
        return data


class DeenPluginAsmX86_64(AsmBase):
    name = 'assembly_x86_64'
    display_name = 'x86_64'
    aliases = ['asm_x86_64',
               'asmx86_64',
               'x86_64',
               'x64']
    cmd_name = 'assembly_x86_64'
    cmd_help='Assemble/Disassemble for the x86_64 architecture'
    keystone_arch = keystone.KS_ARCH_X86 if KEYSTONE else None
    keystone_mode = keystone.KS_MODE_64 if KEYSTONE else None
    capstone_arch = capstone.CS_ARCH_X86 if KEYSTONE else None
    capstone_mode = capstone.CS_MODE_64 if KEYSTONE else None

    def _syntax_highlighting(self, data):
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
            # When pygments is available, we
            # can print the disassembled
            # instructions with syntax
            # highlighting.
            data = highlight(data, NasmLexer(), FORMATTER)
        except ImportError:
            pass
        finally:
            data = data.encode()
        return data
