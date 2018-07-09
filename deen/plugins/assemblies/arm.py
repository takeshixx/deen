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
    cmd_name = 'assembly_x86'
    cmd_help='Assemble/Disassemble for the ARM architecture'
    keystone_arch = keystone.KS_ARCH_ARM
    keystone_mode = keystone.KS_MODE_ARM
    capstone_arch = capstone.CS_ARCH_ARM
    capstone_mode = capstone.CS_MODE_ARM

    def __init__(self):
        super(DeenPluginAsmArm, self).__init__()
        # Initialize keystone and capstone as soon as an instance
        # of this plugin will be created.
        self.ks = keystone.Ks(self.keystone_arch, self.keystone_mode)
        self.cs = capstone.Cs(self.capstone_arch, self.capstone_mode)


class DeenPluginAsmArmThumb(AsmBase):
    name = 'assembly_armthumb'
    display_name = 'ARM Thumb'
    aliases = ['asm_armthumb',
               'thumb']
    cmd_name = 'assembly_armthumb'
    cmd_help='Assemble/Disassemble for the ARM architecture with Thumb instructions'
    keystone_arch = keystone.KS_ARCH_ARM
    keystone_mode = keystone.KS_MODE_THUMB
    capstone_arch = capstone.CS_ARCH_ARM
    capstone_mode = capstone.CS_MODE_THUMB

    def __init__(self):
        super(DeenPluginAsmArmThumb, self).__init__()
        # Initialize keystone and capstone as soon as an instance
        # of this plugin will be created.
        self.ks = keystone.Ks(self.keystone_arch, self.keystone_mode)
        self.cs = capstone.Cs(self.capstone_arch, self.capstone_mode)
