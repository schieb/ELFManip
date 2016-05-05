#! /usr/bin/env python
''' This file is used to test ELFManip during development
    necessary for avoiding isinstance() and type() issues

'''

import sys
from ELFManip import ELFManip

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print "Usage: %s [file1] ([file2] ... [filen])" % sys.argv[0]
        exit()
    
    for elf_filename in sys.argv[1:]:
        print "working on %s" % elf_filename
        elf = ELFManip(elf_filename)
        
        
        #hash_table_section = "/mnt/hgfs/GitHub/Delinker/tests/hash_table"
        #new_RX_section = "/mnt/hgfs/GitHub/Delinker/tests/RX_new"
        
        section1 = "./test_segment"
        section2 = "./test_segment"
        
        section1_addr = 0x09000000;
        section2_addr = 0x07000000;
        
        section = elf.add_section(section1, sh_addr = section1_addr)
        if section is None:
            print "section add failure"
            exit()
        section = elf.add_section(section2, sh_addr = section2_addr)
        if section is None:
            print "section add failure"
            exit()
        #elf.set_entry_point(0x090753a2) # gcc::_start()
        
        elf.write_new_elf(elf.filename + ".new")
    
    
