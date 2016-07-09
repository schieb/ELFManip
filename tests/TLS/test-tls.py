'''
 What happens when we add a TLS section to an executable that already has TLS section(s).
 
 Where will it be placed in memory relative to the other TLS sections?
 If there is a .tbss sections, will the new section be loaded after *ALL OF* the .tbss section contents?
'''
import sys
sys.path.append("../../src")
from Constants import *
from ELFManip import ELFManip, Custom_Section, Custom_Segment


elf_filename = "test-tls"
NUM_REQUESTED_SEGMENTS = 2


def main():
    
    elf = ELFManip(elf_filename, num_adtl_segments=NUM_REQUESTED_SEGMENTS)
    
    old_num_phdrs = elf.phdrs['max_num']
    new_phdr_offset = elf.relocate_phdrs()
    
    if elf.phdrs['max_num'] < old_num_phdrs + NUM_REQUESTED_SEGMENTS:
        print "failed to secure %d additional segment header entries" % NUM_REQUESTED_SEGMENTS
        exit()
    
    
    newbytes_filename = '/tmp/newbytes-tls'
    with open(newbytes_filename, 'r') as f:
        newbytes = f.read()
    
    newbytes_section = Custom_Section(newbytes, sh_addr = 0x0804d000, sh_flags= SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR | SHF_TLS)
    
    # make sure the section is loaded into memory so memcpy will work
    newbytes_segment = Custom_Segment(PT_LOAD)
    elf_segment = elf.add_segment(newbytes_segment)
    if elf_segment is not None:
        elf.add_section(newbytes_section, newbytes_segment)
    
    
    newbytes_segment = Custom_Segment(PT_TLS)
    elf_segment = elf.add_segment(newbytes_segment)
    if elf_segment is not None:
        elf.add_section(newbytes_section, newbytes_segment)
        
    
    
        
    elf.write_new_elf(elf.filename + ".new")

if __name__ == "__main__":
    main()
