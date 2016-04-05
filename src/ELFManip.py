#! /usr/bin/env python

'''
TODO:
    Must-dos:
    - propogate rearchitecture to write_new_elf()
        - need more automation, less hard-coding during section writing and segment updating
        - move program headers into free space between segments (segment padding) if there is enough room
    - add method to move program headers into the .note.* sections (and move .interp)
    
    Features:
    - option to name the section when adding it
    - specify section attributes


'''
 
 
from Constants import *

from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_sh_flags

import struct
import os
import sys
from shutil import copy

import logging
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
        if self.image_base != 0x08048000:
            logger.error("strange image base 0x%08x. Need to check that no code assumes 0x08048000 as the base", self.image_base)
            exit()
        
        
        self.custom_sections = []
        self.custom_segments = [] # segment(s) to hold the custom sections
        
        self.phdrs = self._init_phdrs()
        self.relocate_phdrs()
        
        
        self.shdrs = self._init_shdrs()
    
        
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
            phdrs['entries'].append(Segment(s['p_type'], s['p_offset'], s['p_vaddr'], s['p_paddr'],
                                            s['p_filesz'], s['p_memsz'], s['p_flags'], s['p_align']))
        return phdrs
    
    def _init_shdrs(self):
        shdrs = {'base': None, 'entries': []}
        # copy all the original section headers from the ELF file
        for s in self.elf.iter_sections():
            shdrs['entries'].append(Section(s['sh_name'], s['sh_type'], s['sh_flags'], 
                                            s['sh_addr'], s['sh_offset'], s['sh_size'], s['sh_link'], 
                                            s['sh_info'], s['sh_addralign'], s['sh_entsize']))
        return shdrs
    
    def relocate_phdrs(self):
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
                
        logger.debug("Sections on either side of the segment padding: [%s, %s]", section_before_padding.name, section_after_padding.name)
        
        free_space_start = section_before_padding['sh_offset'] + section_before_padding['sh_size']
        free_space_size = section_after_padding['sh_offset'] - free_space_start
        
        logger.debug("Found %d bytes of padding. Thats enough for %d entries of size %d each.",
                     free_space_size, free_space_size / self.elf.header.e_phentsize, self.elf.header.e_phentsize)
        
        # assume we need space for at least one more entry
        minimum_required_space = (self.elf.header.e_phnum + 1) * self.elf.header.e_phentsize
        if free_space_size >= minimum_required_space:
            logger.debug("Found enough space to move the program headers!")
        else:
            logger.error("Not enough space to relocate the program headers. Try repurposing the GNU_STACK entry" + \
                        " or moving the .interp section and removing the .note.* sections")
            exit()
            
        # ensure that this space is actually empty
        with open(self.filename) as f:
            f.seek(section_before_padding['sh_offset'] + section_before_padding['sh_size'])
            padding_bytes = f.read(free_space_size)
            for b in padding_bytes:
                assert b == "\x00"
                
        #TODO: check using a sound method (i.e., check that there is not a section located in these bytes, 
        # also section headers and program headers could technically be located here
        # basically we need to check everything before we can say for sure that this space is unused
        
        self.phdrs['base'] = free_space_start
        self.phdrs['max_num'] = free_space_size / self.elf.header.e_phentsize
    
    def add_section(self, section_contents, **kwargs):
        ''' Add a section to the ELF file with contents of section_contents
            A segment will automatically be created for each added section
            
            @param section_contents: filename holding the contents of the section
            @param kwargs: optional custom section properties as defined in the ELF spec
        
        '''
        # initialize the section and save it in custom_sections
        self.custom_sections.append(Custom_Section(section_contents, **kwargs))
        # do the same with its corresponding segment
        self._add_segment(self.custom_sections[-1], self.custom_sections[-1].sh_addr)
        
    def _add_segment(self, section, load_addr):
        # add a segment that will contain all of the sections in 'sections'
        #TODO: convert to use self.phdrs['entries']
        new_segment = Custom_Segment([section], load_addr)
        self.phdrs['entries'].append(new_segment)
        
        
    
    def write_from_file(self, out_file, in_file):
        ''' Writes in_file to the current file offset of out_file
            
            @param out_file: output file
            @param in_file: input file
        '''
        with open(in_file, "rb") as in_f:
            for chunk in iter_chunks(in_f):
                if chunk is None:
                    break
                out_file.write(chunk)
        
    def write_new_elf(self, outfile):
        if outfile == self.filename:
            logger.error("Must specify a different file destination than the original ELF")
            exit()
        if len(self.custom_sections) == 0:
            logger.error("Not writing new ELF - you must specify at least one new section first") 
            return
        
        logger.info("Writing new ELF: %s", outfile)
        # copy the entire file first
        copy(self.filename, outfile)
        with open(outfile, "r+b") as f:
            # we must (I strongly believe) add padding_len to cover all of the .bss section
            #    or more generally the last section (if it is of type NOBITS)
            #self.padBss(f)
            
            # append all the section contents, patching in the sh_addr and sh_offset fields as they are concretized
            f.seek(0, os.SEEK_END)
            for section in self.custom_sections:
                if len(self.custom_sections) != 1:
                    # only handling one section for now
                    logger.error("too many custom sections - you supplied %d custom sections", len(self.custom_sections))
                    exit()
                
                current = f.tell()
                
                # pad to section alignment
                #padding_len = section.sh_addralign - (current % section.sh_addralign)
                padding_len = PAGESIZE - (current % PAGESIZE)
                logger.debug("padding EOF with %d null bytes", padding_len)
                f.write("\x00" * padding_len)
                
                # add extra page worth of padding (hardcoded to handle small bss for now)
                #TODO: test with this PAGESIZE padding removed later
                logger.debug("padding EOF with additional 0x%x null bytes", PAGESIZE)
                f.write("\x00" * PAGESIZE)
                
                section_offset = f.tell()
                
                logger.debug("section offset for '%s': 0x%08x", section.filename, section_offset)
                exit()
                
                # append the secton contents
                self.write_from_file(f, section.filename)
                section_end = f.tell()
                
                # update the offset and size fields in the section header entry
                #section.sh_addr = self.image_base + section_offset
                
                #TODO: determine this programatically as the next available page address
                section.sh_addr = 0x08046000 
                #section.sh_addr = 0x0804c000 # one page after bss
                #section.sh_vaddr = self.offset_to_vaddr(section_offset)
                section.sh_offset = section_offset
                section.sh_size = section_end - section_offset
            
            
            # we are adding the segment every time a custom section is added
            #self._add_segment(self.custom_sections, 0x08046000)
            #elf._add_segment(self.custom_sections, 0x0804c000)
            
            
            logger.error("start here")
            exit()
            
            #TODO: make the function write_section_headers() that writes both normal and custom section header entries
            #        also remove get_section_headers() and use self.sections instead
            # copy the section headers to the current file offset (end of the file)
            current = f.tell()
            padding_len = 0x10 - (current % 0x10)
            f.write("\x00" * padding_len)
            new_sh_offset = f.tell()
            section_headers = self.get_section_headers()
            f.write(section_headers)
            
            
            logger.info("Appending %d section header entries", len(self.custom_sections))
            f.write(''.join(section.dump_entry() for section in self.custom_sections))
            
            
            
            # copy the program headers to the end of the file
            current = f.tell()
            padding_len = 0x10 - (current % 0x10)
            
            f.write("\x00" * padding_len)
            new_ph_offset = f.tell()
            
            program_headers = self.get_program_headers()
            f.write(program_headers)
            
            
            
            logger.info("Appending %d program header entries", len(self.custom_sections))
            f.write(''.join(segment.dump_entry() for segment in self.custom_segments))
            
            
            new_entry_point = self.elf.header.e_entry # use default entry point for now
            
            self.patch_elf_header(f, new_entry_point, new_sh_offset, len(self.custom_sections), new_ph_offset, len(self.custom_segments))
            #self.patch_elf_header(f, new_entry_point, new_sh_offset, len(self.custom_sections) , None, len(self.custom_segments))
            
            
            
            # patch the program header R/X segment in a hack way for testing
            # p_vaddr
            #f.seek(PH_START + 32*2 + 4*2)
            #f.write(struct.pack("<i", 0x08047000))
            
            #TODO: wrap this into a funciton to update an arbitrary segment header entry
            # PHDR entry:
            # p_offset
            f.seek(new_ph_offset + 32*0 + 4*1)
            f.write(struct.pack("<i", new_ph_offset))
            
            # p_vaddr
            f.seek(new_ph_offset + 32*0 + 4*2)
            f.write(struct.pack("<i", self.image_base + new_ph_offset))
            
            
            # first LOAD segment:
            # p_filsz
            f.seek(new_ph_offset + 32*2 + 4*4)
            old_size = struct.unpack("<i", f.read(4))[0]
            new_size = old_size + 0x4000 +  self.custom_sections[0].sh_size
            f.seek(new_ph_offset + 32*2 + 4*4)
            f.write(struct.pack("<i", new_size))
            
            # p_memsz
            f.seek(new_ph_offset + 32*2 + 4*5)
            f.write(struct.pack("<i", new_size))
            
            
            # debugging bus error...
            # pad to 0x3000 then write the file again
            
            f.seek(0, 2)
            current = f.tell()
            print hex(current)
            
            padding_len = 0x3000 - current
            f.write("\x00" * padding_len)
            print hex(f.tell())
            
            self.write_from_file(f, self.custom_sections[0].filename)
            print hex(f.tell())
    
    
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
        
    def get_section_headers(self):
        sh_offset = self.elf.header.e_shoff
        num_entries = self.elf.header.e_shnum
        entry_size = self.elf.header.e_shentsize
        with open(self.filename, "rb") as f:
            f.seek(sh_offset)
            section_headers = f.read(num_entries * entry_size)
            
        return section_headers
    
    def get_program_headers(self):
        ph_offset = self.elf.header.e_phoff
        num_entries = self.elf.header.e_phnum
        entry_size = self.elf.header.e_phentsize
        with open(self.filename, "rb") as f:
            f.seek(ph_offset)
            program_headers = f.read(num_entries * entry_size)
            
        return program_headers
    
    def patch_elf_header(self, f, new_entry_point, new_sh_offset, num_new_sh, new_ph_offset, num_new_ph):
        #with open(filename, "r+b")
        f.seek(EP_OFFSET)
        f.write(struct.pack("<i", new_entry_point))
        
        f.seek(SH_OFFSET)
        f.write(struct.pack("<i", new_sh_offset))
        f.seek(NUM_SH_OFFSET)
        f.write(struct.pack("<h", self.elf.header.e_shnum + num_new_sh))
        
        if new_ph_offset is not None:
            f.seek(PH_OFFSET)
            f.write(struct.pack("<i", new_ph_offset))
            f.seek(NUM_PH_OFFSET)
            f.write(struct.pack("<h", self.elf.header.e_phnum + num_new_ph))

class Section(object):
    ''' The basic section class.
        This class is only to be used to copy the section headers from the original ELF file
        
        User-defined sections must be instanciated via the Custom_Section class
    '''
    def __init__(self, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize):
        
        self.sh_name = sh_name # randomish name from the section header string table
        self.sh_type = sh_type
        self.sh_flags = sh_flags
        self.sh_addr = sh_addr
        self.sh_offset = sh_offset
        self.sh_size = sh_size
        self.sh_link = sh_link
        self.sh_info = sh_info
        self.sh_addralign = sh_addralign
        self.sh_entsize = sh_entsize
        
    
    def get_next_offset(self):
        ''' Determines the file offset at which this section will be placed in the ELF 
        '''
        pass
        
        
    def dump_entry(self):
        if self.sh_offset is None:
            print "section backed by file '%s' does not have an ELF offset assigned" % self.filename
            exit()
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
    
    '''
    def __init__(self, contents, sh_type=SHT_PROGBITS, sh_flags=PF_X | PF_W | PF_R, sh_addr=None):
        '''
        @param contents: file containing section contents
        '''
        super(self.__class__, self).__init__(0x1f,
                                             sh_type,
                                             sh_flags,
                                             sh_addr,
                                             None,
                                             None,
                                             SHN_UNDEF,
                                             0,
                                             0x10,
                                             0)
        self.filename = contents
        
        self._update_size()
        
        print "Created custom section from file '%s'" % self.filename
        self.describe_section()
        
    
    def _update_size(self):
        ''' Set the size of the section to match the size of the file that is backing the section
        '''
        if self.sh_size is None or self.sh_size == 0:
            print self.filename
            self.sh_size = os.path.getsize(self.filename)
        
    

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
    def __init__(self, sections, load_addr):
        ''' 
        Just like a Segment except we need to do special things to make sure that the segments are mapped correctly
        
        @param sections: the sections that this segment will map into memory
        @note: for now we are only accepting one section per segment.
                    handling multiple sections should not be too hard or a feature to add
        @param load_addr: the virtual address at which the section belonging to this segment
                    will be loaded into
        '''
        self.sections = sections
        assert len(self.sections) == 1
        print self.sections
        print self.sections[0]
        print type(self.sections[0])
        
        assert isinstance(self.sections[0], Custom_Section)
        
        super(self.__class__, self).__init__(PT_LOAD,
                                             self._get_p_offset(),
                                             load_addr,
                                             load_addr,
                                             self._get_p_filesz(),
                                             self._get_p_filesz(), # assuming no new bss
                                             self._union_section_flags(),
                                             0x1000)
    
    
    def _get_p_offset(self):
        # find the minimum file offset of all the sections
        p_offset = None
        for section in self.sections:
            if p_offset is None:
                p_offset = section.sh_offset
            elif p_offset > section.sh_offset:
                p_offset = section.sh_offset
        return p_offset
    
    def _get_p_filesz(self):
        return sum(section.sh_size for section in self.sections)
    
    def _union_section_flags(self):
        return PF_X | PF_W | PF_R
        '''
        flags = PF_R
        for section in self.sections:
            if section.sh_flags & SHF_EXECINSTR:
                flags |= PF_X
            if section.sh_flags & SHF_WRITE:
                flags |= PF_W
        return flags
        '''
        
    
def iter_chunks(file_object, block_size=1024):
    while True:
        data = file_object.read(block_size)
        if not data:
            yield None
        yield data


