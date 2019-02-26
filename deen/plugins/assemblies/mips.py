try:
    import keystone
except ImportError:
    keystone = None
try:
    import capstone
except ImportError:
    capstone = None

from .__base__ import AsmBase


class DeenPluginAsmMips(AsmBase):
    name = 'assembly_mips'
    display_name = 'MIPS'
    aliases = ['asm_mips',
               'mips32',
               'mips']
    cmd_name = 'assembly_mips'
    cmd_help='Assemble/Disassemble for the MIPS architecture'
    keystone_arch = keystone.KS_ARCH_MIPS \
        if (keystone and hasattr(keystone, 'KS_ARCH_MIPS')) else None
    keystone_mode = keystone.KS_MODE_MIPS32 \
        if (keystone and hasattr(keystone, 'KS_MODE_MIPS32')) else None
    capstone_arch = capstone.CS_ARCH_MIPS \
        if (capstone and hasattr(capstone, 'CS_ARCH_MIPS')) else None
    capstone_mode = capstone.CS_MODE_MIPS32 \
        if (capstone and hasattr(capstone, 'CS_MODE_MIPS32')) else None

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None,
                      *args, **kwargs):
        # Add an additional argument for big endian mode.
        parser = AsmBase.add_argparser(argparser, cmd_name,
                                       cmd_help, cmd_aliases=cmd_aliases)
        parser.add_argument('-e', '--big-endian', dest='bigendian',
                            default=False, help='use big endian',
                            action='store_true')


class DeenPluginAsmMips64(DeenPluginAsmMips):
    name = 'assembly_mips64'
    display_name = 'MIPS64'
    aliases = ['asm_mips64',
               'mips64']
    cmd_name = 'assembly_mips64'
    cmd_help='Assemble/Disassemble for the MIPS64 architecture'
    keystone_arch = keystone.KS_ARCH_MIPS \
        if (keystone and hasattr(keystone, 'KS_ARCH_MIPS')) else None
    keystone_mode = keystone.KS_MODE_MIPS64 \
        if (keystone and hasattr(keystone, 'KS_MODE_MIPS64')) else None
    capstone_arch = capstone.CS_ARCH_MIPS \
        if (capstone and hasattr(capstone, 'CS_ARCH_MIPS')) else None
    capstone_mode = capstone.CS_MODE_MIPS64 \
        if (capstone and hasattr(capstone, 'CS_MODE_MIPS64')) else None
