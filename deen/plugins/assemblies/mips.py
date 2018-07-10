try:
    import keystone
    import capstone
    KEYSTONE = True
except ImportError:
    KEYSTONE = False

from .__base__ import AsmBase


class DeenPluginAsmMips(AsmBase):
    name = 'assembly_mips'
    display_name = 'MIPS'
    aliases = ['asm_mips',
               'mips32',
               'mips']
    cmd_name = 'assembly_mips'
    cmd_help='Assemble/Disassemble for the MIPS architecture'
    keystone_arch = keystone.KS_ARCH_MIPS
    keystone_mode = keystone.KS_MODE_MIPS32
    capstone_arch = capstone.CS_ARCH_MIPS
    capstone_mode = capstone.CS_MODE_MIPS32

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None):
        # Add an additional argument for big endian mode.
        parser = AsmBase.add_argparser(argparser, cmd_name,
                                       cmd_help, cmd_aliases=cmd_aliases)
        parser.add_argument('-e', '--big-endian', dest='bigendian',
                            default=False, help='use big endian',
                            action='store_true')


class DeenPluginAsmMips64(AsmBase):
    name = 'assembly_mips64'
    display_name = 'MIPS64'
    aliases = ['asm_mips64',
               'mips64']
    cmd_name = 'assembly_mips64'
    cmd_help='Assemble/Disassemble for the MIPS64 architecture'
    keystone_arch = keystone.KS_ARCH_MIPS
    keystone_mode = keystone.KS_MODE_MIPS64
    capstone_arch = capstone.CS_ARCH_MIPS
    capstone_mode = capstone.CS_MODE_MIPS64

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None):
        # Add an additional argument for big endian mode.
        parser = AsmBase.add_argparser(argparser, cmd_name,
                                       cmd_help, cmd_aliases=cmd_aliases)
        parser.add_argument('-b', '--big-endian', dest='bigendian',
                            default=False, help='use big endian',
                            action='store_true')
