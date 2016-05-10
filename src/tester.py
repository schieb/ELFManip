#! /usr/bin/env python
''' This file is used to test ELFManip during development
    necessary for avoiding isinstance() and type() issues

'''

import sys
import os
from ELFManip import ELFManip, Custom_Section, Custom_Segment
from Constants import PT_LOAD

def get_filesize(filename):
    return os.path.getsize(filename)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: %s [file1]" % sys.argv[0]
        exit()
        
    elf_filename = sys.argv[1]
    elf = ELFManip(elf_filename)
    
    filename = '../tests/erick/newbytes'
    with open(filename, 'r') as f:
        newbytes = f.read()
    
    newbytes_section = Custom_Section(newbytes, sh_addr = 0x09000000)
    if newbytes_section is None:
        print "add_section failure -- aborting"
        continue
    
    newbytes_segment = Custom_Segment(PT_LOAD)
    elf_segment = elf.add_segment(my_segment)
    elf.add_section(newbytes_section, my_segment)
    
    #elf_segment.register_section(newbytes_section)
    
    elf.set_entry_point(0x092e221e)
    
    elf.write_new_elf(elf.filename + ".new")
    
    


