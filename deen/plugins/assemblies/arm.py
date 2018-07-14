try:
    import keystone
    import capstone
    KEYSTONE = True
except ImportError:
    KEYSTONE = False

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
    keystone_arch = keystone.KS_ARCH_ARM if KEYSTONE else None
    keystone_mode = keystone.KS_MODE_ARM if KEYSTONE else None
    capstone_arch = capstone.CS_ARCH_ARM if KEYSTONE else None
    capstone_mode = capstone.CS_MODE_ARM if KEYSTONE else None

    @staticmethod
    def add_argparser(argparser, cmd_name, cmd_help, cmd_aliases=None):
        # Add an additional argument for big endian mode.
        parser = AsmBase.add_argparser(argparser, cmd_name,
                                       cmd_help, cmd_aliases=cmd_aliases)
        parser.add_argument('-b', '--big-endian', dest='bigendian',
                            default=False, help='use big endian',
                            action='store_true')


class DeenPluginAsmArmThumb(DeenPluginAsmArm):
    name = 'assembly_armthumb'
    display_name = 'ARM Thumb'
    aliases = ['asm_armthumb',
               'thumb']
    cmd_name = 'assembly_armthumb'
    cmd_help='Assemble/Disassemble for the ARM architecture with Thumb instructions'
    keystone_arch = keystone.KS_ARCH_ARM if KEYSTONE else None
    keystone_mode = keystone.KS_MODE_THUMB if KEYSTONE else None
    capstone_arch = capstone.CS_ARCH_ARM if KEYSTONE else None
    capstone_mode = capstone.CS_MODE_THUMB if KEYSTONE else None
