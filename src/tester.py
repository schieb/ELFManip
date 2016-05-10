#! /usr/bin/env python
''' This file is used to test ELFManip during development
    necessary for avoiding isinstance() and type() issues

'''

import sys
import os
from ELFManip import ELFManip, Custom_Section, Custom_Segment
from Constants import PT_LOAD, PF_R

def get_filesize(filename):
    return os.path.getsize(filename)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: %s [file1]" % sys.argv[0]
        exit()
        
    elf_filename = sys.argv[1]
    elf = ELFManip(elf_filename)
    
    '''
    original_phdr_size = len(elf.get_ph_table())
    desired_phdr_offset = os.path.getsize(elf_filename) # at EOF
    
    # create the segment that will map in the program headers for us
    phdr_segment = Custom_Segment(PT_LOAD, p_offset=desired_phdr_offset, p_vaddr=0x08000000, p_paddr=0x08000000, 
                                  p_filesz=original_phdr_size, p_memsz=original_phdr_size, p_flags=PF_R)
    
    actual_phdr_offset = elf.relocate_phdrs(desired_phdr_offset, original_phdr_size + (32*2), phdr_segment) # want 2 new entries of 32 bytes each
    
    # test reordering the phdrs; putting phdr_segment just after the segment of type PHDR (if present)
    phdr_segment = elf.phdrs['entries'].pop()
    elf.phdrs['entries'].insert(0, phdr_segment)
    '''
    
    actual_phdr_offset = elf.relocate_phdrs()
    
    filename = '../tests/erick/newbytes'
    with open(filename, 'r') as f:
        newbytes = f.read()
    
    newbytes_section = Custom_Section(newbytes, sh_addr = 0x09000000)
    newbytes_segment = Custom_Segment(PT_LOAD)
    elf_segment = elf.add_segment(newbytes_segment)
    elf.add_section(newbytes_section, newbytes_segment)
    
    
    elf.set_entry_point(0x092e221e)
    
    elf.write_new_elf(elf.filename + ".new")
    
    


