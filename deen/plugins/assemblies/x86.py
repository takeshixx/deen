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

