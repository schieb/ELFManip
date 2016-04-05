#! /usr/bin/env python
''' This file is used to test ELFManip during development
    necessary for avoiding isinstance() and type() issues

'''

import sys
from ELFManip import ELFManip


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print "Usage: %s [ELF file] [new section contents] [hexadecimal vma of new section]" % sys.argv[0]
        exit()
    
    elf_filename = sys.argv[1]
    section_contents = sys.argv[2]
    section_vma = sys.argv[3]
    
    elf = ELFManip(elf_filename)
    
    elf.add_section(section_contents, sh_addr = int(section_vma, 16))
    
    elf.write_new_elf(elf.filename + ".new")
    
    
