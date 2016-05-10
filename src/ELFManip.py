#! /usr/bin/env python

'''
TODO:
    Must-dos:
    - ability to *always* be able to relocate the program headers
    - ability to specify a section's file offset field (currently ignored and overwritten when writing the ELF)
        - would require intelligent book-keeping when adding and writing sections to the ELF file 
    
    Features:
    - option to name the section when adding it


'''
 
 
from Constants import (SHF_WRITE,
                       SHF_EXECINSTR,
                       SHN_UNDEF,
                       SHT_PROGBITS,
                       SHT_NOBITS,
                       PF_X, PF_W, PF_R,
                       PT_LOAD,
                       PT_PHDR,
                       )

from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_sh_flags, describe_p_type
from elftools.elf.enums import ENUM_SH_TYPE, ENUM_P_TYPE

import struct
import os
from shutil import copy

import logging
from elftools.elf.constants import SH_FLAGS
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(levelname)s   %(module)s.%(funcName)s :: %(message)s'))
logger.addHandler(sh)
logger.propagate = False

EP_OFFSET       = 0x18
PH_OFFSET       = 0x1c
SH_OFFSET       = 0x20
NUM_PH_OFFSET   = 0x2c
NUM_SH_OFFSET   = 0x30

PH_START        = 52

PAGESIZE = 0x1000

class BadELF(RuntimeError):
    ''' raised when the ELF cannot be processed by ELFManip 
        e.g., unexpected section/segment layout, missing sections/segments
    '''

class ELFManip(object):
    def __init__(self, in_file):
        '''
        @param in_file: the ELF executable
        '''
        self.filename = in_file
        self._f = open(self.filename, "rb")
        self.elf = ELFFile(self._f)
        
        self.image_base = self._get_image_base()
        logger.info("Image base: 0x%08x", self.image_base)
        
        
        #TODO: replace custom_sections with functions that interface wth Custom_Segment objects inside self.phdrs['entries']
        #      add differentiation between unbacked sections and sections backed by a segment
        self.custom_sections = []
        
        self.shdrs = self._init_shdrs()
        
        self.phdrs = self._init_phdrs()
        self.relocate_phdrs()
        
        self.new_entry_point = None
    
    
    def _get_image_base(self):
        base = None
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":
                if base is None:
                    base = segment.header.p_vaddr
                elif base > segment.header.p_vaddr:
                    base = segment.header.p_vaddr
        return base
    
    def _init_phdrs(self):
        phdrs = {'base': None, 'max_num': self.elf['e_phnum'], 'entries': []}
        # copy all the original program headers from the ELF file
        for s in self.elf.iter_segments():
            phdrs['entries'].append(Segment(ENUM_P_TYPE[s['p_type']], s['p_offset'], s['p_vaddr'], s['p_paddr'],
                                            s['p_filesz'], s['p_memsz'], s['p_flags'], s['p_align']))
        logger.debug("Copying %d program headers from %s", len(phdrs['entries']), self.filename)
        return phdrs
    
    def _init_shdrs(self):
        shdrs = {'base': None, 'entries': []}
        # copy all the original section headers from the ELF file
        for s in self.elf.iter_sections():
            shdrs['entries'].append(Section(s['sh_name'], ENUM_SH_TYPE[s['sh_type']], s['sh_flags'], 
                                            s['sh_addr'], s['sh_offset'], s['sh_size'], s['sh_link'], 
                                            s['sh_info'], s['sh_addralign'], s['sh_entsize']))
        logger.debug("Copying %d section headers from %s", len(shdrs['entries']), self.filename)
        return shdrs
    
    def relocate_phdrs(self):
        ''' Attempts to find a new location for the program headers to reside in the ELF image
        
        '''
        #TODO: rename this function
        # find the gap between 'AX' and 'WA' segments
        logger.debug("Looking for sufficient padding between LOAD segments to relocate the PHDRs to")
        section_before_padding = None
        section_after_padding = None
        
        #TODO: generalize this to handle unordered section header entries
        for section in self.elf.iter_sections():
            if section['sh_flags'] & SHF_WRITE:
                section_after_padding = section
                break
            else:
                section_before_padding = section
        
        if section_before_padding is None:
            logger.error("Cannot relocate the program headers.")
            raise BadELF("ELF has no sections")
        elif section_after_padding is None:
            logger.error("Cannot relocate the program headers.")
            raise BadELF("ELF has no ELF file has no writable section")
            
        logger.debug("Sections on either side of the segment padding: [%s, %s]", section_before_padding.name, section_after_padding.name)
        
        free_space_start = section_before_padding['sh_offset'] + section_before_padding['sh_size']
        free_space_size = section_after_padding['sh_offset'] - free_space_start
        
        logger.debug("Found 0x%x bytes of padding at offset 0x%x. Thats enough for %d entries of size %d each.",
                     free_space_size, free_space_start, free_space_size / self.elf.header.e_phentsize, self.elf.header.e_phentsize)
        
        # assume we need space for at least one more entry
        minimum_required_space = (self.elf.header.e_phnum + 1) * self.elf.header.e_phentsize
        if free_space_size >= minimum_required_space:
            logger.debug("Found enough space to move the program headers!")
            
            # check that this space is actually empty
            empty = True
            with open(self.filename) as f:
                f.seek(section_before_padding['sh_offset'] + section_before_padding['sh_size'])
                padding_bytes = f.read(free_space_size)
                for b in padding_bytes:
                    if b != "\x00":
                        empty = False
                if not empty:
                    # not sure why this would ever happen in a legitimate binary
                    logger.warn("Padding is not empty... repurposing anyways")
                    
            self._update_phdr_entry(free_space_start, free_space_size)
            
        else:
            logger.warn("Not enough space to relocate the program headers. Try repurposing the GNU_STACK entry" + \
                        " or moving the .interp section and removing the .note.* sections")
            logger.warn("Temporary hack to give you ability to add *one* section (which will be mapped by one segment).")
            
            for idx, segment in enumerate(self.elf.iter_segments()):
                if describe_p_type(segment['p_type']) == "GNU_STACK":
                    # keep the old base and max number of entries
                    self.phdrs['base'] = self.elf.header['e_phoff']
                    self.phdrs['max_num'] = len(self.phdrs['entries'])
                    # remove this entry, freeing up room for one user defined entry
                    logger.debug("removing GNU_STACK pdhr entry")
                    del self.phdrs['entries'][idx]
                    
                    #assert describe_p_type(gnu_stack_entry.p_type) == "GNU_STACK"
                    logger.info("should have room to add one section/segment")
                    break
        
    def _update_phdr_entry(self, new_base, max_size):
        ''' Update the PHDR entry in (executable ELF files) to match the new location of the program headers
            @param new_base: offset at which the program headers will be located
            @param max_size: maximum size in bytes that the new program headers can grow to
        '''
        
        self.phdrs['base'] = new_base
        self.phdrs['max_num'] = max_size / self.elf.header.e_phentsize
        
        # update the offset in the PHDR segment entry
        for p in self.phdrs['entries']:
            # Note: shared objects have no phdr entry in segment headers
            if p.p_type == PT_PHDR:
                logger.debug("Updating the PHDR segment to new offset: 0x%x", self.phdrs['base'])
                p.p_offset = self.phdrs['base']
                p.p_vaddr = self.image_base + p.p_offset
                p.p_paddr = self.image_base + p.p_offset
                p.p_filesz = len(self.phdrs['entries']) * 32 # 32 bytes each
                p.p_memsz = p.p_filesz
        
        # expand the size of the LOAD segment that contains the enlarged program headers
        # otherwise, the page may not get mapped into memory
        found = False
        for segment in self.phdrs['entries']:
            if segment.p_type != PT_LOAD:
                continue
            if segment.p_offset + segment.p_filesz == new_base:
                found = True
                segment.p_filesz += len(self.get_ph_table())
                segment.p_memsz  = segment.p_filesz
                break
                
        if not found:
            logger.error("problem finding LOAD segment containing new phdr location")
            raise BadELF("can't find LOAD segment")
        
        
    def write_phdrs(self, outfile):
        outfile.seek(self.phdrs['base'])
        logger.debug("Writing program headers to offset 0x%x", outfile.tell())
        outfile.write(self.get_ph_table())
    
    
    def add_section(self, section, segment=None):
        assert isinstance(section, Custom_Section)
        if segment is not None:
            assert isinstance(segment, Custom_Segment)
            segment.register_section(section)
            
        self.custom_sections.append(section)
        
        
    def add_segment(self, segment):
        assert isinstance(segment, Custom_Segment)
        # check for room in program headers for a new entry
        if len(self.phdrs['entries']) < self.phdrs['max_num']:
            self.phdrs['entries'].append(segment)
        else:
            logger.error("Cannot add another section. Not enough room in the program headers to add another segment")
            return None
        return self.phdrs['entries'][-1]
        
    def get_sh_table(self):
        ''' Get the section header table which includes all of the original section header entries
            plus all of the entries for the custom sections
        '''
        ret = ''.join(s.dump_entry() for s in self.shdrs['entries'])
        ret += ''.join(s.dump_entry() for s in self.custom_sections)
        return ret
    
    def get_ph_table(self):
        ''' Get the program header table which includes all of the original program header entries
            plus all of the entries for the custom segments
        '''
        for phdr in self.phdrs['entries']:
            if isinstance(phdr, Custom_Segment):
                phdr.finalize()
        return ''.join(p.dump_entry() for p in self.phdrs['entries'])
    
    def set_section_offset(self, section, offset):
        section.sh_offset = offset
        section.segment.p_offset = offset
        
    def write_new_elf(self, outfile):
        if outfile == self.filename:
            logger.error("Must specify a different file destination than the original ELF")
            return
        if len(self.custom_sections) == 0:
            logger.error("Not writing new ELF - you must specify at least one new section first") 
            return
        
        logger.info("Writing new ELF: %s", outfile)
        # copy the entire file first
        copy(self.filename, outfile)
        with open(outfile, "r+b") as f:
            # append all the section contents, patching in the sh_addr and sh_offset fields as they are concretized
            f.seek(0, os.SEEK_END)
            
            for phdr in self.phdrs['entries']:
                if not isinstance(phdr, Custom_Segment):
                    continue
                for section in phdr.sections:
                    pad_to_modulus(f, PAGESIZE)
                    pad_to_modulus(f, PAGESIZE, pad_if_aligned=True)
                    section_offset = f.tell()
                    f.write(section.contents)
                    
                    section.sh_offset = section_offset
            
            """
            for section in self.custom_sections:
                
                # NOTE: the addition of padding was not tested very much
                #        it could be the case that we can get away with padding less
                #        basically I am attempting to play it safe
                
                # pad to section alignment
                pad_to_modulus(f, PAGESIZE)
                
                # add extra page worth of padding
                pad_to_modulus(f, PAGESIZE, pad_if_aligned=True)
                
                section_offset = f.tell()
                
                logger.debug("section offset for '%s': 0x%08x", section.filename, section_offset)
                
                # append the secton contents
                write_from_file(f, section.filename)
                section_end = f.tell()
                
                
                self.set_section_offset(section, section_offset)
            """
            
            # copy the section headers to the current file offset (end of the file)
            pad_to_modulus(f, 0x10)
            
            new_sh_offset = f.tell()
            
            logger.info("Appending %d section header entries (%d + %d)", len(self.shdrs['entries']) + len(self.custom_sections),
                        len(self.shdrs['entries']), len(self.custom_sections))
            f.write(self.get_sh_table())
            
            
            # copy the program headers to the space that was determined in relocate_phdrs
            self.write_phdrs(f)
            
            self.patch_elf_header(f, new_sh_offset, self.phdrs['base'])
            
            logger.info("finished writing ELF")
    
    def offset_to_vaddr(self, offset):
        # find the last section with attribute ALLOC
        last_alloc_section = None
        for section in self.elf.iter_sections():
            if "A" in describe_sh_flags(section['sh_flags']):
                if last_alloc_section is None:
                    last_alloc_section = section
                elif section['sh_addr'] > last_alloc_section['sh_addr']:
                    last_alloc_section = section
        
        next_available_spot = last_alloc_section['sh_addr'] + last_alloc_section['sh_size']
        #TODO: finish this function
    
    def get_program_headers(self):
        ph_offset = self.elf.header.e_phoff
        num_entries = self.elf.header.e_phnum
        entry_size = self.elf.header.e_phentsize
        with open(self.filename, "rb") as f:
            f.seek(ph_offset)
            program_headers = f.read(num_entries * entry_size)
            
        return program_headers
    
    def set_entry_point(self, entry_point):
        self.new_entry_point = entry_point
    
    def patch_elf_header(self, f, new_sh_offset, new_ph_offset):
        if self.new_entry_point is not None:
            f.seek(EP_OFFSET)
            f.write(struct.pack("<i", self.new_entry_point))
        
        f.seek(SH_OFFSET)
        f.write(struct.pack("<i", new_sh_offset))
        f.seek(NUM_SH_OFFSET)
        f.write(struct.pack("<h", len(self.shdrs['entries']) + len(self.custom_sections)))
        
        if new_ph_offset is not None:
            f.seek(PH_OFFSET)
            f.write(struct.pack("<i", new_ph_offset))
            f.seek(NUM_PH_OFFSET)
            f.write(struct.pack("<h", len(self.phdrs['entries'])))

class Section(object):
    ''' The basic section class.
        This class is only to be used to copy the section headers from the original ELF file
        
        User-defined sections must be instanciated via the Custom_Section class
    '''
    def __init__(self, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize):
        
        self.sh_name = sh_name
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_addralign = sh_addralign
        self.sh_entsize = sh_entsize
        
        self.segment = None # defined when a segment is created for this section
        
    
    def get_next_offset(self):
        ''' Determines the file offset at which this section will be placed in the ELF 
        '''
        pass
        
        
    def dump_entry(self):
        return struct.pack("<10i", 
                           self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, 
                           self.sh_offset, self.sh_size, self.sh_link, self.sh_info, 
                           self.sh_addralign, self.sh_entsize)
        
    def describe_section(self):
        print "Name: 0x%x, Type: %s, Flags: %s, Addr: 0x%08x, Offset: %s, Size: %s bytes, Link: %s, Info: %s, Align: %d, EntSz: %d" % \
                (self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, 
                 self.sh_offset, self.sh_size, self.sh_link, self.sh_info, 
                 self.sh_addralign, self.sh_entsize)
        

class Custom_Section(Section):
    ''' 
        TODO: sections cannot be given a specific file offset, instead it is determined when the ELF file is written
                user might want control over this
    '''
    def __init__(self, contents='', sh_type=SHT_PROGBITS, sh_flags=PF_X | PF_W | PF_R, sh_addr=None):
        '''
        @param contents: file containing section contents
        '''
        super(self.__class__, self).__init__(0x1f, # randomish name from the section header string table
                                             sh_type,
                                             sh_flags,
                                             sh_addr,
                                             None,
                                             None,
                                             SHN_UNDEF,
                                             0,
                                             0x10,
                                             0)
        self.contents = contents
        if self.sh_size is None:
            self.sh_size = len(contents)
        
        print "Created custom section:"
        self.describe_section()
    
    def is_defined(self):
        for attr in [self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset, self.sh_size, 
                     self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize]:
            if attr is None:
                return False
        return True

class Segment(object):
    def __init__(self, p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align):
        self.p_type = p_type
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr # unspecified contents by System V
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags
        self.p_align = p_align
        
    def dump_entry(self):
        return struct.pack("<8i", 
                           self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
                           self.p_filesz, self.p_memsz, self.p_flags, self.p_align)

class Custom_Segment(Segment):
    def __init__(self, p_type, p_offset=None, p_vaddr=None, p_paddr=None, p_filesz=None, p_memsz=None, p_flags=None, p_align=0x1000):
        ''' 
        Just like a Segment except we need to do special things to make sure that the segments are mapped correctly
        
        '''
        
        super(self.__class__, self).__init__(p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align)
        
        self.sections = []
    
        
    def register_section(self, section):
        ''' associate section with this segment
        '''
        assert isinstance(section, Custom_Section)
        self.sections.append(section)
    
    def _get_p_filesz(self):
        if len(self.sections) == 0:
            return 0
        
        sections_sorted = sorted(self.sections, key=lambda s: s.sh_addr)
        first = sections_sorted[0]
        last = sections_sorted[-1]
        if last.sh_type == SHT_NOBITS:
            filesz = last.sh_addr - first.sh_addr
        else:
            filesz = last.sh_addr + last.sh_size - first.sh_addr
        
        return filesz
    
    def _get_p_memsz(self):
        if len(self.sections) == 0:
            return 0
        
        sections_sorted = sorted(self.sections, key=lambda s: s.sh_addr)
        first = sections_sorted[0]
        last = sections_sorted[-1]
        
        return last.sh_addr + last.sh_size - first.sh_addr
    
    def _union_section_flags(self):
        flags = PF_R
        for section in self.sections:
            if section.sh_flags & SHF_EXECINSTR:
                flags |= PF_X
            if section.sh_flags & SHF_WRITE:
                flags |= PF_W
        return flags
    
    def finalize(self):
        ''' call after all sections have been added to this segment and those sections properties are also finalized
            this will attempt to fill in all the correct phdr values with respect to the sections that have been registered
        '''
        for section in self.sections:
            assert section.is_defined() == True
        self.p_offset = min((section.sh_offset for section in self.sections))
        self.p_vaddr = min((section.sh_addr for section in self.sections))
        self.p_paddr = self.p_vaddr
        self.p_filesz = self._get_p_filesz()
        self.p_memsz = self._get_p_memsz()
        self.p_flags = self._union_section_flags()


def pad_to_modulus(f, modulus, padding_bytes='\x00', pad_if_aligned=False):
    ''' Pad file object f using padding_bytes
        @param f: file-like object
        @param modulus: when to stop adding the padding
        @param padding_bytes: bytes to use as padding (will be chopped if they wont fit evenly in the pad)
                                if this is not desired, ensure that pad_size % len(padding_bytes) == 0
        @param pad_if_aligned: add padding if file offset is already aligned to modulus?
    '''
    current = f.tell()
    if pad_if_aligned == False and current % modulus == 0:
        return
    if padding_bytes == '':
        return
    
    padding_len = modulus - (current % modulus)
    logger.debug("padding EOF with %d null bytes", padding_len)
    f.write(padding_bytes * (padding_len / len(padding_bytes)) + padding_bytes[:padding_len % len(padding_bytes)])
    

def write_from_file(out_file, in_file):
    ''' Writes in_file to the current file offset of out_file
        
        @param out_file: output file
        @param in_file: input file
    '''
    with open(in_file, "rb") as in_f:
        for chunk in iter_chunks(in_f):
            if chunk is None:
                break
            out_file.write(chunk)
    
def iter_chunks(file_object, block_size=1024):
    while True:
        data = file_object.read(block_size)
        if not data:
            yield None
        yield data


