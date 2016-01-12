# Various sizes
SYMTAB_ENTRY_SIZE   = 16
ELFHDR_SIZE         = 52 # 0x34
SHDR_ENTRY_SIZE     = 40 # 0x28
RELOCTAB_ENTRY_SIZE = 8

# Section header index
SHN_UNDEF     = 0
SHN_LORESERVE = 0xff00
SHN_LOPROC    = 0xff00
SHN_HIPROC    = 0xff1f
SHN_ABS       = 0xfff1
SHN_COMMON    = 0xfff2
SHN_HIRESERVE = 0xffff

#Section header type
SHT_NULL     = 0
SHT_PROGBITS = 1
SHT_SYMTAB   = 2
SHT_STRTAB   = 3
SHT_RELA     = 4
SHT_HASH     = 5
SHT_DYNAMIC  = 6
SHT_NOTE     = 7
SHT_NOBITS   = 8
SHT_REL      = 9
SHT_SHLIB    = 10
SHT_DYNSYM   = 11
SHT_LOPROC   = 0x70000000
SHT_HIPROC   = 0x7fffffff
SHT_LOUSER   = 0x80000000
SHT_HIUSER   = 0xffffffff

#Section header flag
SHF_WRITE       = 0x1
SHF_ALLOC       = 0x2
SHF_EXECINSTR   = 0x4
SHF_MASKPROC    = 0xf0000000

#Symbol table index
STN_UNDEF = 0

#Symbol binding
STB_LOCAL  = 0
STB_GLOBAL = 1
STB_WEAK   = 2
STB_LOPROC = 13
STB_HIPROC = 15

#Symbol type
STT_NOTYPE  = 0
STT_OBJECT  = 1
STT_FUNC    = 2
STT_SECTION = 3
STT_FILE    = 4
STT_LOPROC  = 13
STT_HIPROC  = 15

#Symbol other field (always zero)
STO_DEFAULT = 0

# Relocation entry::Type of reference
R_386_32   = 1 # (absolute)
R_386_PC32 = 2 # (indirect)