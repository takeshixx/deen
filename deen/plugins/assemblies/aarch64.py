try:
    import keystone
    import capstone
    KEYSTONE = True
except ImportError:
    KEYSTONE = False

from .__base__ import AsmBase


class DeenPluginAsmAarch64(AsmBase):
    name = 'assembly_aarch64'
    display_name = 'AARCH64'
    aliases = ['asm_aarch64',
               'aarch64',
               'arm64']
    cmd_name = 'assembly_aarch64'
    cmd_help='Assemble/Disassemble for the AARCH64 architecture'
    keystone_arch = keystone.KS_ARCH_ARM64 if KEYSTONE else None
    capstone_arch = capstone.CS_ARCH_ARM64 if KEYSTONE else None

    def __init__(self):
        super(DeenPluginAsmAarch64, self).__init__()
        # Initialize keystone and capstone as soon as an instance
        # of this plugin will be created.
        if KEYSTONE:
            self.ks = keystone.Ks(self.keystone_arch, keystone.KS_MODE_LITTLE_ENDIAN)
            self.cs = capstone.Cs(self.capstone_arch, keystone.KS_MODE_LITTLE_ENDIAN)
