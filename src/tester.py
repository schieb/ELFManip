#! /usr/bin/env python
''' This file is used to test ELFManip during development
    necessary for avoiding isinstance() and type() issues

'''

import sys
from ELFManip import ELFManip
from Mappin import HASH_TABLE_BASE, NEW_TEXT_BASE 

if __name__ == "__main__":
    if len(sys.argv) != 2:
        #print "Usage: %s [ELF file] [new section contents] [hexadecimal vma of new section]" % sys.argv[0]
        print "Usage: %s [ELF file]" % sys.argv[0]
        exit()
    
    elf_filename = sys.argv[1]
    
    elf = ELFManip(elf_filename)
    
    
    hash_table_section = "/mnt/hgfs/GitHub/Delinker/tests/hash_table"
    new_RX_section = "/mnt/hgfs/GitHub/Delinker/tests/RX_new"
    
    elf.add_section(hash_table_section, sh_addr = HASH_TABLE_BASE)
    elf.add_section(new_RX_section, sh_addr = NEW_TEXT_BASE)
    elf.set_entry_point(NEW_TEXT_BASE)
    
    elf.write_new_elf(elf.filename + ".new")
    
    
