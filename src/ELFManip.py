from Constants import *

from elftools.elf.elffile import ELFFile

import struct
import os
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

class ELFManip:
    def __init__(self, in_file):
        '''
        @param in_file: the ELF executable
        '''
        self.filename = in_file
        self._f = open(self.filename, "rb")
        self.elf = ELFFile(self._f)
        
        self.image_base = self._get_image_base()
        logger.info("Image base: 0x%08x", self.image_base)
        
        self.new_sections = []
        self.new_segments = [] # segment(s) to hold the new sections
        
    def _get_image_base(self):
        base = None
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":
                if base is None:
                    base = segment.header.p_vaddr
                elif base > segment.header.p_vaddr:
                    base = segment.header.p_vaddr
        return base
    
    
    class Section():
        def __init__(self, contents):
            '''
            @param contents: file containing section contents
            '''
            self.filename = contents
            
            # elements with value None are defined when the section is written to the output file
            self.sh_name = 0
            self.sh_type = SHT_PROGBITS
            self.sh_flags = SHF_ALLOC | SHF_EXECINSTR | SHF_WRITE
            self.sh_addr = None
            self.sh_offset = None
            self.sh_size = None
            self.sh_link = SHN_UNDEF
            self.sh_info = 0
            self.sh_addralign = 0x10
            self.sh_entsize = 0
        
        def dump_entry(self):
            return struct.pack("<10i", 
                               self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, 
                               self.sh_offset, self.sh_size, self.sh_link, self.sh_info, 
                               self.sh_addralign, self.sh_entsize)
            
    class Segment():
        def __init__(self, sections, load_addr):
            ''' 
            @param sections: list of Sections that will be added to the ELF
            @param load_addr: the virtual address at which the sections belonging to this segment
                        will be loaded at
            '''
            self.sections = sections
            
            self.p_type = PT_LOAD
            self.p_offset = self._get_p_offset()
            self.p_vaddr = load_addr
            self.p_paddr = self.p_vaddr # unspecifid contents by System V
            self.p_filesz = self._get_p_filesz()
            self.p_memsz = self.p_filesz # assuming no new bss
            self.p_flags = self._union_section_flags()
            self.p_align = 0x1000
        
        
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
            flags = PF_R
            for section in self.sections:
                if section.sh_flags & SHF_EXECINSTR:
                    flags |= PF_X
                elif section.sh_flags & SHF_WRITE:
                    flags |= PF_W
            return flags
        
        def dump_entry(self):
            return struct.pack("<8i", 
                               self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
                               self.p_fileze, self.p_memsz, self.flags, self.p_align)
        
    
            
    def add_section(self, contents):
        self.new_sections.append(self.Section(contents))
        
    def add_segment(self, sections, load_addr):
        # add a segment that will contain all of the sections in 'sections'
        self.new_segments.append(self.Segment(sections, load_addr))
        
    
    def write_from_file(self, out_file, in_file):
        with open(in_file, "rb") as in_f:
            for chunk in iter_chunks(in_f):
                if chunk is None:
                    break
                out_file.write(chunk)
        
    def write_new_elf(self, outfile):
        if outfile == self.filename:
            logger.error("Must specify a different file destination than the original ELF")
            exit()
        if len(self.new_sections) == 0:
            logger.error("Not writing mew ELF - you must specify new sections to add first") 
            return
        
        # copy the entire file first
        copy(self.filename, outfile)
        with open(outfile, "a+b") as f:
            # append all the section contents, patching in the sh_addr and sh_offset fields as they are concretized
            f.seek(0, os.SEEK_END)
            for section in self.new_sections:
                current = f.tell()
                
                # pad to section alignment
                padding = section.sh_addralign - (current % section.sh_addralign)
                f.write("\x00"*padding)
                section_offset = current + padding
                
                # append the secton contents
                self.write_from_file(f, section.filename)
                section_end = f.tell()
                
                # update the offset and size fields in the section header entry
                section.sh_addr = self.image_base + section_offset
                section.sh_offset = section_offset
                section.sh_size = section_end - section_offset
            
            
            self.add_segment(self.new_sections, 0x09000000)
            
            # copy the section headers to the end of the file
            current = f.tell()
            padding = 0x10 - (current % 0x10)
            f.write("\x00" * padding)
            new_sh_offset = f.tell()
            section_headers = self.get_section_headers()
            f.write(section_headers)
            
            logger.log_info("Appending %d section header entries", len(self.new_sections))
            f.write(''.join(section.dump_entry() for section in self.new_sections))
            
            # copy the program headers to the end of the file
            current = f.tell()
            padding = 0x10 - (current % 0x10)
            f.write("\x00" * padding)
            new_ph_offset = f.tell()
            program_headers = self.get_program_headers()
            f.write(program_headers)
            
            logger.log_info("Appending %d program header entries", len(self.new_sections))
            f.write(''.join(section.dump_entry() for section in self.new_sections))
            
            new_entry_point = self.elf.header.e_entry # use default entry point for now
            self.patch_elf_header(f, new_entry_point, new_sh_offset, len(self.new_sections), new_ph_offset, len(self.new_segments))
    
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
        f.seek(EP_OFFSET)
        f.write(struct.pack("<i", new_entry_point))
        
        f.seek(SH_OFFSET)
        f.write(struct.pack("<i", new_sh_offset))
        f.seek(NUM_SH_OFFSET)
        f.write(struct.pack("<h", self.elf.header.e_shnum + num_new_sh))
        
        f.seek(PH_OFFSET)
        f.write(struct.pack("<i", new_ph_offset))
        f.seek(NUM_PH_OFFSET)
        f.write(struct.pack("<h", self.elf.header.e_phnum + num_new_ph))
        
        
def iter_chunks(file_object, block_size=1024):
    while True:
        data = file_object.read(block_size)
        if not data:
            yield None
        yield data
        