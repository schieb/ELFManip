#! /usr/bin/env python
''' This file is used to test ELFManip during development
    necessary for avoiding isinstance() and type() issues

'''

import sys
from ELFManip import ELFManip


if __name__ == "__main__":
    if len(sys.argv) != 2:
        #print "Usage: %s [ELF file] [new section contents] [hexadecimal vma of new section]" % sys.argv[0]
        print "Usage: %s [ELF file]" % sys.argv[0]
        exit()
    
    elf_filename = sys.argv[1]
    
    elf = ELFManip(elf_filename)
    
    
    section_contents = "/mnt/hgfs/GitHub/Delinker/tests/test_section"
    section_vma = 0x09000000
    
    elf.add_section(section_contents, sh_addr = section_vma)
    
    elf.write_new_elf(elf.filename + ".new")
    
    
