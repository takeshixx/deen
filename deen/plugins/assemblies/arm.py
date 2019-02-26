try:
    import keystone
except ImportError:
    keystone = None
try:
    import capstone
except ImportError:
    capstone = None

from .__base__ import AsmBase


class DeenPluginAsmArm(AsmBase):
    name = 'assembly_arm'
    display_name = 'ARM'
    aliases = ['asm_arm',
               'asmarm',
               'assemble_arm',
               'assemblearm',
               'arm']
    cmd_name = 'assembly_arm'
    cmd_help='Assemble/Disassemble for the ARM architecture'
    keystone_arch = keystone.KS_ARCH_ARM \
        if (keystone and hasattr(keystone, 'KS_ARCH_ARM')) else None
    keystone_mode = keystone.KS_MODE_ARM \
        if (keystone and hasattr(keystone, 'KS_MODE_ARM')) else None
    capstone_arch = capstone.CS_ARCH_ARM \
        if (capstone and hasattr(capstone, 'CS_ARCH_ARM')) else None
    capstone_mode = capstone.CS_MODE_ARM \
        if (capstone and hasattr(capstone, 'CS_MODE_ARM')) else None

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None,
                      *args, **kwargs):
        # Add an additional argument for big endian mode.
        parser = AsmBase.add_argparser(argparser, cmd_name,
                                       cmd_help, cmd_aliases=cmd_aliases)
        parser.add_argument('-b', '--big-endian', dest='bigendian',
                            default=False, help='use big endian',
                            action='store_true')

    def _syntax_highlighting(self, data):
        try:
            from pygments import highlight
            from pygments.lexers import GasLexer
            from pygments.formatters import TerminalFormatter, Terminal256Formatter
            from pygments.styles import get_style_by_name
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
            data = highlight(data, GasLexer(), FORMATTER)
        except ImportError:
            pass
        finally:
            data = data.encode()
        return data


class DeenPluginAsmArmThumb(DeenPluginAsmArm):
    name = 'assembly_armthumb'
    display_name = 'ARM Thumb'
    aliases = ['asm_armthumb',
               'thumb']
    cmd_name = 'assembly_armthumb'
    cmd_help='Assemble/Disassemble for the ARM architecture with Thumb instructions'
    keystone_arch = keystone.KS_ARCH_ARM \
        if (keystone and hasattr(keystone, 'KS_ARCH_ARM')) else None
    keystone_mode = keystone.KS_MODE_THUMB \
        if (keystone and hasattr(keystone, 'KS_MODE_THUMB')) else None
    capstone_arch = capstone.CS_ARCH_ARM \
        if (capstone and hasattr(capstone, 'CS_ARCH_ARM')) else None
    capstone_mode = capstone.CS_MODE_THUMB \
        if (capstone and hasattr(capstone, 'CS_MODE_THUMB')) else None
