'''
 What happens when we add a TLS section to an executable that already has TLS section(s).
 
 Where will it be placed in memory relative to the other TLS sections?
 If there is a .tbss sections, will the new section be loaded after *ALL OF* the .tbss section contents?
'''
import sys
sys.path.append("../../src")
from Constants import *
from ELFManip import ELFManip, Custom_Section, Custom_Segment


NUM_REQUESTED_SEGMENTS = 2


def main(filename):
    
    elf = ELFManip(filename, num_adtl_segments=NUM_REQUESTED_SEGMENTS)
    
    old_num_phdrs = elf.phdrs['max_num']
    new_phdr_offset = elf.relocate_phdrs()
    
    if elf.phdrs['max_num'] < old_num_phdrs + NUM_REQUESTED_SEGMENTS:
        print "failed to secure %d additional segment header entries" % NUM_REQUESTED_SEGMENTS
        exit()
    
    
    newbytes_filename = './newbytes-tls'
    with open(newbytes_filename, 'r') as f:
        newbytes = f.read()
    
    newbytes_section = Custom_Section(newbytes, sh_addr = 0x09000000, sh_flags= SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR | SHF_TLS)
    
    # make sure the section is loaded into memory so the loader doesnt fail on memcpy
    newbytes_segment = Custom_Segment(PT_LOAD)
    pt_load_segment = elf.add_segment(newbytes_segment)
    if pt_load_segment is not None:
        pt_load_section = elf.add_section(newbytes_section, newbytes_segment)
    
    # normally, each section that belongs to a segment will be written to the ELF at write time.
    # however, this is special in that two segments are mapping the "same" section
    # so, ELFManip can see that newbytes_section was (at this point) already associated with a segment
    # and it will point this new segment to the already present section contents instead of writing the section contents again
    
    newbytes_segment = Custom_Segment(PT_TLS, p_align=4)
    #                                         Note the alignment. without this, it segfaults...
    pt_tls_segment = elf.add_segment(newbytes_segment)
    if pt_tls_segment is not None:
        pt_tls_section = elf.add_section(newbytes_section, newbytes_segment)
       
    # note that there are two section headers for the same section
    # this doesn't actually matter since the section headers are not used to load the ELF 
    #elf.ehdr['e_shnum'] -= 1
    
    elf.write_new_elf(elf.filename + ".new")

if __name__ == "__main__":
    filename = sys.argv[1]
    main(filename)
