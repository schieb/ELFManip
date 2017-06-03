#! /usr/bin/env python
''' This file is used to test ELFManip during development
    necessary for avoiding isinstance() and type() issues

'''

import sys

from elfmanip import ELFManip, CustomSection, CustomSegment
from constants import PT_LOAD, PF_R

NUM_REQUESTED_SEGMENTS = 2

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: %s [file]" % sys.argv[0]
        exit()

    elf_filename = sys.argv[1]
    elf = ELFManip(elf_filename, num_adtl_segments=NUM_REQUESTED_SEGMENTS)

    old_num_phdrs = elf.phdrs['max_num']

    new_phdr_offset = elf.relocate_phdrs()

    if elf.phdrs['max_num'] < old_num_phdrs + NUM_REQUESTED_SEGMENTS:
        print "failed to secure %d additional segment header entries" % NUM_REQUESTED_SEGMENTS
        exit()


    filename = '../tests/erick/newbytes'
    with open(filename, 'r') as f:
        newbytes = f.read()

    newbytes_section = CustomSection(newbytes, sh_addr=0x09000000)
    newbytes_segment = CustomSegment(PT_LOAD)
    elf_segment = elf.add_segment(newbytes_segment)
    if elf_segment is not None:
        elf.add_section(newbytes_section, newbytes_segment)


    newbytes_section = CustomSection(newbytes, sh_addr=0x07000000)
    newbytes_segment = CustomSegment(PT_LOAD)
    elf_segment = elf.add_segment(newbytes_segment)
    if elf_segment is not None:
        elf.add_section(newbytes_section, newbytes_segment)

    '''
    newbytes_section = CustomSection(newbytes, sh_addr = 0x06000000)
    newbytes_segment = CustomSegment(PT_LOAD)
    elf_segment = elf.add_segment(newbytes_segment)
    if elf_segment is not None:
        elf.add_section(newbytes_section, newbytes_segment)
    '''


    # elf.set_entry_point(0x092e221e)

    elf.write_new_elf(elf.filename + ".new")




