'''
Shows uses of CustomSection and CustomSegment
'''
import sys

import logging
logger = logging.getLogger("elfmanip")
logger.setLevel(10)

from elfmanip import ELFManip, CustomSection, CustomSegment, constants

NUM_REQUESTED_SEGMENTS = 2
ELF_FILENAME = "test"
NEWBYTES = "A"*128

if __name__ == "__main__":

    elf = ELFManip(ELF_FILENAME, num_adtl_segments=NUM_REQUESTED_SEGMENTS)

    old_num_phdrs = elf.phdrs['max_num']

    new_phdr_offset = elf.relocate_phdrs(use_methods=[elf._phdr_hack3])

    if elf.phdrs['max_num'] < old_num_phdrs + NUM_REQUESTED_SEGMENTS:
        print "failed to secure %d additional segment header entries" % NUM_REQUESTED_SEGMENTS
        exit()

    newbytes_section = CustomSection(NEWBYTES, sh_addr=0x07000000)
    newbytes_segment = CustomSegment(constants.PT_LOAD)
    elf_segment = elf.add_segment(newbytes_segment)
    if elf_segment is not None:
        elf.add_section(newbytes_section, newbytes_segment)

    newbytes_section = CustomSection(NEWBYTES, sh_addr=0x09000000)
    newbytes_segment = CustomSegment(constants.PT_LOAD)
    elf_segment = elf.add_segment(newbytes_segment)
    if elf_segment is not None:
        elf.add_section(newbytes_section, newbytes_segment)


    # elf.set_entry_point(0x092e221e)

    elf.write_new_elf(elf.filename + ".new")
