'''
 What happens when we add a TLS section to an executable that already has TLS section(s).

 Where will it be placed in memory relative to the other TLS sections?
 If there is a .tbss sections, will the new section be loaded after *ALL OF* the .tbss section contents?
'''
import sys

from elfmanip import ELFManip, CustomSection, CustomSegment
from elftools.elf.elffile import ELFFile


NUM_REQUESTED_SEGMENTS = 2

tls_section_added = False
tls_section_contents = b''
tls_section_offset = 0

def add_tls_section(fname, contents):
    # This does not require ELFManip because it must
    # be called earlier on, before we actually rewrite the
    # binary, because I need the new TLS offset.
    # We could obviously create the ELFManip object now,
    # but it won't be used again until we write it out at
    # the end.
    global tls_section_added
    global tls_section_contents
    tls_section_added = True
    # Pad contents to 4-byte alignment
    tls_section_contents = contents + ('\0' * (4 - len(contents) % 4))
    with open(fname) as f:
        elf = ELFFile(f)
       	for s in elf.iter_segments():
            # Assume only one TLS segment exists (will fail on an already modified binary)
            if s.header['p_type'] == 'PT_TLS':
                tls_section_offset = s.header['p_memsz'] + len(tls_section_contents)
                print 'old section is 0x%x (%x with padding)' % (s.header['p_memsz'], s.header['p_memsz'] + (4 - s.header['p_memsz'] % 4))
                print 'new content is 0x%x (%x with padding)' % (len(contents), len(contents) + (4 - len(contents) % 4))
                print 'overall        0x%x (%x with padding)' % (tls_section_offset, tls_section_offset + (4 - tls_section_offset % 4))
                return tls_section_offset + (4 - tls_section_offset % 4)
    return len(contents) + (4 - len(contents) % 4)  # If there is no TLS segment

def get_tls_content(elf):
    # For now assume that the TLS sections are adjacent and
    # we can append their contents directly
    # I also am assuming that there will probably be only
    # two sections, .tdata and .tbss, which seems likely.
    # This may work under different circumstances but it is
    # hard to predict.
    content = b''
    if tls_section_added:
        content += tls_section_contents
    print 'length of new contents: 0x%x' % len(content)
    for entry in elf.shdrs['entries']:
        if (entry.sh_flags & SHF_TLS) == SHF_TLS:
            if entry.sh_type == SHT_NOBITS:  # bss has no contents
                content += '\0' * entry.sh_size  # fill bss space with 0
                print 'adding .tbss section of length: 0x%x' % entry.sh_size
            else:
                content += entry.contents
                print 'adding .tdata section of length: 0x%x' % len(entry.contents)
    return content


def main(filename):

    elf = ELFManip(filename, num_adtl_segments=NUM_REQUESTED_SEGMENTS)

    new_data = "data that will hopefully go into thread local storage"
    print 'ADDING TLS SECTION'

    off = add_tls_section(filename, new_data)
    print 'New data starting at offset %d (0x%x)' % (off, off)
    print 'CONTENTS (length %d) ARE %s' % (len(tls_section_contents), tls_section_contents)

    # print '---TLS SECTIONS---'
    # print elf.shdrs['entries'][18] #.tdata
    # print elf.shdrs['entries'][19] #.tbss

    # elf.shdrs['entries'][18].sh_size = 0x17+0x100



    old_num_phdrs = elf.phdrs['max_num']
    new_phdr_offset = elf.relocate_phdrs()

    if elf.phdrs['max_num'] < old_num_phdrs + NUM_REQUESTED_SEGMENTS:
        print "failed to secure %d additional segment header entries" % NUM_REQUESTED_SEGMENTS
        exit()


    # newbytes_filename = './newbytes-tls'
    # with open(newbytes_filename, 'r') as f:
    #    newbytes = f.read()
    newbytes = get_tls_content(elf)
    print 'newbytes is %s' % newbytes
    print 'newbyte length: 0x%x' % len(newbytes)

    '''if len(newbytes)%4 != 0:
        print 'newbytes not aligned %d'%len(newbytes)
        newbytes+='\0'*(4-len(newbytes)%4) #Pad to 4-byte alignment
        print 'newbytes now aligned %d'%len(newbytes)
    print 'adding old tls data (plus bss?) (maybe because I don\'t give room for the bss section in the segment?)'
    newbytes+=elf.shdrs['entries'][18].contents
    #IF the .tdata section's end is aligned, no padding needs to go here.  IF!  If not, well, I need to check.
    #newbytes+='\0' #Hard to determine how much padding needs to go here...
    newbytes+='Z'*(elf.shdrs['entries'][19].sh_size)'''

    # newbytes_filename2 = './newbytes-tls2'
    # with open(newbytes_filename2, 'r') as f:
    #    newbytes2 = f.read()

    newbytes_section = CustomSection(newbytes, sh_addr=0x09000000, sh_type=SHT_PROGBITS, sh_flags=SHF_WRITE | SHF_ALLOC | SHF_TLS, sh_addralign=0x4)
    # newbytes_section2 = CustomSection(newbytes2, sh_addr =0x09001000, sh_type=SHT_NOBITS, sh_flags= SHF_WRITE | SHF_ALLOC | SHF_TLS)

    # make sure the section is loaded into memory so the loader doesnt fail on memcpy
    newbytes_segment = CustomSegment(PT_LOAD)
    pt_load_segment = elf.add_segment(newbytes_segment)
    if pt_load_segment is not None:
        pt_load_section = elf.add_section(newbytes_section, newbytes_segment)

    # newbytes_segment2 = CustomSegment(PT_LOAD)
    # pt_load_segment = elf.add_segment(newbytes_segment2)
    # if pt_load_segment is not None:
    #    pt_load_section = elf.add_section(newbytes_section2, newbytes_segment2)

    # normally, each section that belongs to a segment will be written to the ELF at write time.
    # however, this is special in that two segments are mapping the "same" section
    # so, ELFManip can see that newbytes_section was (at this point) already associated with a segment
    # and it will point this new segment to the already present section contents instead of writing the section contents again

    newbytes_segment = CustomSegment(PT_TLS, p_align=4)
    #                                         Note the alignment. without this, it segfaults...
    pt_tls_segment = elf.add_segment(newbytes_segment)
    if pt_tls_segment is not None:
        pt_tls_section = elf.add_section(newbytes_section, newbytes_segment)

    # newbytes_segment2 = CustomSegment(PT_TLS, p_align=4)
    #                                          Note the alignment. without this, it segfaults...
    # pt_tls_segment = elf.add_segment(newbytes_segment2)
    # if pt_tls_segment is not None:
    #    pt_tls_section = elf.add_section(newbytes_section2, newbytes_segment2)

    # note that there are two section headers for the same section
    # this doesn't actually matter since the section headers are not used to load the ELF
    # elf.ehdr['e_shnum'] -= 1

    elf.write_new_elf(elf.filename + ".new")

if __name__ == "__main__":
    filename = sys.argv[1]
    main(filename)
