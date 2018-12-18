try:
    import keystone
    import capstone
    KEYSTONE = True
except ImportError:
    KEYSTONE = False

from .arm import DeenPluginAsmArm


class DeenPluginAsmAarch64(DeenPluginAsmArm):
    name = 'assembly_aarch64'
    display_name = 'AARCH64'
    aliases = ['asm_aarch64',
               'aarch64',
               'arm64']
    cmd_name = 'assembly_aarch64'
    cmd_help='Assemble/Disassemble for the AARCH64 architecture'
    keystone_arch = keystone.KS_ARCH_ARM64 \
        if (KEYSTONE and hasattr(keystone, 'KS_ARCH_ARM64')) else None
    keystone_mode = 0 # There is only the default mode for AARCH64
    capstone_arch = capstone.CS_ARCH_ARM64 \
        if (KEYSTONE and hasattr(keystone, 'CS_ARCH_ARM64')) else None
    capstone_mode = 0 # There is only the default mode for AARCH64
