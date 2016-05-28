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
                       SHT_NOTE,
                       SHT_HASH,
                       SHT_REL, SHT_RELA,
                       SHT_SYMTAB,
                       SHT_DYNAMIC,
                       SHT_DYNSYM,
                       SHT_GNU_verdef,
                       SHT_GNU_verneed,
                       SHT_GNU_versym,
                       PF_X, PF_W, PF_R,
                       PT_LOAD,
                       PT_PHDR,
                       PT_INTERP,
                       )

from elftools.elf.elffile import ELFFile
from elftools.elf.descriptions import describe_sh_flags, describe_p_type
from elftools.elf.enums import ENUM_SH_TYPE, ENUM_P_TYPE, ENUM_E_TYPE, ENUM_E_MACHINE, ENUM_E_VERSION

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


PAGESIZE = 0x1000

class BadELF(RuntimeError):
    ''' raised when the ELF cannot be processed by ELFManip 
        e.g., unexpected section/segment layout, missing sections/segments
    '''

class ELFManip(object):
    def __init__(self, in_file, num_adtl_segments=1):
        '''
        @param in_file: the ELF executable
        @param num_adtl_segments: the number of additional segments requested
        '''
        self.filename = in_file
        self._f = open(self.filename, "rb")
        self.elf = ELFFile(self._f)
        self.num_adtl_segments = num_adtl_segments
        
        self.image_base = self._get_image_base()
        logger.info("Image base: 0x%08x", self.image_base)
        
        
        #TODO: replace custom_sections with functions that interface wth Custom_Segment objects inside self.phdrs['entries']
        #      add differentiation between unbacked sections and sections backed by a segment
        self.custom_sections = []
        
        self.ehdr = self._init_ehdr()
        self.phdrs = self._init_phdrs()
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
        phdrs = {'base': self.ehdr['e_phoff'], 
                 'max_num': self.elf['e_phnum'], 
                 'size': self.ehdr['e_phentsize'] * self.ehdr['e_phnum'], 
                 'entries': []}
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
            if s['sh_type'] == SHT_NOBITS:
                contents = ''
            else:
                self.elf.stream.seek(s['sh_offset'])
                contents = self.elf.stream.read(s['sh_size'])
            shdrs['entries'].append(Section(s['sh_name'], ENUM_SH_TYPE[s['sh_type']], s['sh_flags'], 
                                            s['sh_addr'], s['sh_offset'], s['sh_size'], s['sh_link'], 
                                            s['sh_info'], s['sh_addralign'], s['sh_entsize'],
                                            contents))
        logger.debug("Copying %d section headers from %s", len(shdrs['entries']), self.filename)
        return shdrs
    
    def _init_ehdr(self):
        return {'e_ident': self.elf.e_ident_raw,
                'e_type': ENUM_E_TYPE[self.elf.header['e_type']],
                'e_machine': ENUM_E_MACHINE[self.elf.header['e_machine']],
                'e_version': ENUM_E_VERSION[self.elf.header['e_version']],
                'e_entry': self.elf.header['e_entry'],
                'e_phoff': self.elf.header['e_phoff'],
                'e_shoff': self.elf.header['e_shoff'],
                'e_flags': self.elf.header['e_flags'],
                'e_ehsize': self.elf.header['e_ehsize'],
                'e_phentsize': self.elf.header['e_phentsize'],
                'e_phnum': self.elf.header['e_phnum'],
                'e_shentsize': self.elf.header['e_shentsize'],
                'e_shnum': self.elf.header['e_shnum'],
                'e_shstrndx': self.elf.header['e_shstrndx'],
                }
        
    def dump_ehdr(self):
        return self.ehdr['e_ident'] + struct.pack("<HHIIIIIHHHHHH",
                                                   self.ehdr['e_type'],
                                                   self.ehdr['e_machine'],
                                                   self.ehdr['e_version'],
                                                   self.ehdr['e_entry'],
                                                   self.ehdr['e_phoff'],
                                                   self.ehdr['e_shoff'],
                                                   self.ehdr['e_flags'],
                                                   self.ehdr['e_ehsize'],
                                                   self.ehdr['e_phentsize'],
                                                   self.ehdr['e_phnum'],
                                                   self.ehdr['e_shentsize'],
                                                   self.ehdr['e_shnum'],
                                                   self.ehdr['e_shstrndx']
                                                   )
    
    def relocate_phdrs(self, new_offset=None, new_size=None, segment=None):
        ''' Attempts to find a new location for the program headers to reside in the ELF image
            @param new_offset: offset to move the phdrs to. if -1, move to the end of the file
            @warning: user should be very careful in specifying new_offset
            @note: new_size should ideally be a multiple of e_phentsize (not enforced)
            @return: location of the new phdrs (could be the original location)
        '''
        if new_offset is not None:
            if new_size is None:
                logger.warn("You must specify the size of the relocated program headers")
                return None
            # take the user's offset as a command - don't ask questions, just do!
            logger.debug("Moving program headers to offset 0x%08x")
            self._update_phdr_entry(new_offset, new_size, segment)
        else:
            self._phdr_hack()
            
        return self.phdrs['base']
        
    def _phdr_hack(self):
        ''' Check for free space in the ELF big enough to store the original program headers plus some extras 
        '''
        logger.debug("Looking for sufficient padding between LOAD segments to relocate the PHDRs to")
        section_before_padding = None
        section_after_padding = None
        
        ############
        # Method 1 #
        ############
        # find the gap between 'AX' and 'WA' segments
        #TODO: generalize this to handle unordered section header entries (legal?)
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
                     free_space_size, free_space_start, free_space_size / self.ehdr['e_phentsize'], self.ehdr['e_phentsize'])
        
        minimum_required_space = (self.ehdr['e_phnum'] + self.num_adtl_segments) * self.ehdr['e_phentsize']
        if free_space_size >= minimum_required_space:
            logger.debug("Found enough space to move the program headers!")
            
            # check that this space is actually empty
            #TODO: use self._f or self.elf instead of reopening the file
            empty = True
            with open(self.filename) as f:
                f.seek(section_before_padding['sh_offset'] + section_before_padding['sh_size'])
                padding_bytes = f.read(free_space_size)
                for b in padding_bytes:
                    if b != "\x00":
                        empty = False
                if not empty:
                    # not sure why this would ever happen in a legitimate binary but issue a warning nonetheless
                    logger.warn("Padding is not empty... repurposing anyways")
                    
            self._update_phdr_entry(free_space_start, free_space_size)
        elif self.num_adtl_segments == 1:
            ############
            # Method 2 #
            ############
            logger.warn("Not enough space to relocate the program headers. Repurposing the GNU_STACK entry")
            logger.warn("Temporary hack to give you ability to add *one* section (which will be mapped by one segment).")
            
            for idx, segment in enumerate(self.elf.iter_segments()):
                if describe_p_type(segment['p_type']) == "GNU_STACK":
                    # keep the old base and max number of entries
                    self.phdrs['base'] = self.ehdr['e_phoff']
                    self.phdrs['max_num'] = len(self.phdrs['entries'])
                    # remove this entry, freeing up room for one user defined entry
                    logger.debug("removing GNU_STACK pdhr entry")
                    del self.phdrs['entries'][idx]
                    
                    #assert describe_p_type(gnu_stack_entry.p_type) == "GNU_STACK"
                    logger.info("should have room to add one section/segment")
                    break
        else:
            ############
            # Method 3 #
            ############
            # move .interp section AND remove any following .note.* sections
            #TODO: if no NOTE sections, ability to move .interp (if doing so would satisfy the requested num of segments) would be nice
            #TODO: assert that the order of sections in the shdrs is correct
            interp_index = 1 # hardcoded and expected location of the .interp section header entry
            shstrtab_offset = self.shdrs['entries'][self.ehdr['e_shstrndx']].sh_offset
            str_offset = self.shdrs['entries'][interp_index].sh_name
            self._f.seek(shstrtab_offset + str_offset)
            name = self._f.read(7)
            
            if name != '.interp':
                logger.warn("Method 3 failed: Unexpected sections.")
                return
            
            # find the last NOTE section in the group of NOTE sections immediately following .interp
            last_note_section = None
            for idx, section in enumerate(self.shdrs['entries']):
                if idx in range(interp_index +1):
                    # skip to the section after .interp
                    continue
                if section.sh_type == SHT_NOTE:
                    last_note_section = idx
                else:
                    break
            if last_note_section is None:
                logger.warn("Method 3 failed: There are no NOTE sections")
                return
            
            num_freed_sections = last_note_section - interp_index
            freed_space = 0
            for section in self.shdrs['entries'][interp_index+1: last_note_section+1]:
                freed_space += section.sh_size
            
            
            # not sure what this was for:
            #num_freed_sections * self.elf.header['e_shentsize']
            
            num_new_phdr_entries = freed_space / self.ehdr['e_phentsize']
            if num_new_phdr_entries >= self.num_adtl_segments:
                logger.debug("Method 3 success!")
            else:
                logger.warn("Method 3 failed: Removing shdr entries did not yield enough space for %d additional phdrs", self.num_adtl_segments)
                return
            
            
            logger.info("removing shdr entries for %d NOTE sections", num_freed_sections)
            logger.info("resulted in room for %d additional program headers", num_new_phdr_entries)
            
            # move shdrs 0 and 1 (NULL, .interp) to overwrite shdrs last_note_section-1 and last_note_section, respectively
            self.shdrs['entries'][last_note_section-1] = self.shdrs['entries'][0]
            self.shdrs['entries'][last_note_section] = self.shdrs['entries'][1]
            
            # remove old NULL and interp shdr entries in reverse order
            for i in xrange(num_freed_sections - 1, -1, -1):
                self.remove_shdr_entry(i)
            
            
            # .interp shdr was moved so now we need to update some of its fields then copy its old contents to the new location
            interp_contents = self.shdrs['entries'][interp_index].get_original_bytes()
            self.shdrs['entries'][interp_index].sh_addr += freed_space
            self.shdrs['entries'][interp_index].sh_offset += freed_space
            self.shdrs['entries'][interp_index].write(interp_contents)
            
            # also, update the INTERP segment
            for segment in self.phdrs['entries']:
                if segment.p_type == PT_INTERP:
                    segment.p_vaddr += freed_space
                    segment.p_paddr += freed_space
                    segment.p_offset += freed_space
            
            # free up the added space by updating the elf header
            self.ehdr['e_shoff'] += num_freed_sections * self.ehdr['e_shentsize']
            
            
            self._update_phdr_entry(self.phdrs['base'], self.phdrs['size'] + freed_space)
        
        
    def _update_phdr_entry(self, new_base, max_size, segment=None):
        ''' Update the PHDR entry in (executable ELF files) to match the new location of the program headers
            @param new_base: offset at which the program headers will be located
            @param max_size: maximum size in bytes that the new program headers can grow to
            TODO: segment parameter is a quick hack and might need to be refactored
        '''
        
        base_changed = True if new_base != self.phdrs['base'] else False
        
        self.phdrs['base'] = new_base
        self.phdrs['max_num'] = max_size / self.ehdr['e_phentsize']
        self.phdrs['size'] = max_size
        
        # update the offset in the PHDR segment entry
        for p in self.phdrs['entries']:
            # Note: shared objects and statically linked executables have no phdr entry in segment headers
            if p.p_type == PT_PHDR:
                logger.debug("Updating the PHDR segment to new offset: 0x%x", self.phdrs['base'])
                p.p_offset = self.phdrs['base']
                p.p_vaddr = self.image_base + p.p_offset
                p.p_paddr = self.image_base + p.p_offset
                p.p_filesz = len(self.phdrs['entries']) * 32 # 32 bytes each
                p.p_memsz = p.p_filesz
        
        if segment is not None:
            # now that the phdrs have sufficient room, we can add the user supplied segment
            logger.debug("Added user defined segment backing the new program headers")
            self.add_segment(segment)
        
        #following assumes that the only time we need to what the segment entry is when the base changed
        # more specifically, we assume that simply *extending* the phdrs in place will grow into a different segment
        elif base_changed:
            # expand the size of the LOAD segment that contains the enlarged program headers
            # otherwise, the page may not get mapped into memory
            found = False
            for segment in self.phdrs['entries']:
                if segment.p_type != PT_LOAD:
                    continue
                if segment.p_offset + segment.p_filesz == new_base:
                    found = True
                    segment.p_filesz += len(self.dump_phdrs())
                    segment.p_memsz  = segment.p_filesz
                    break
                    
            if not found:
                logger.error("problem finding LOAD segment containing new phdr location")
                raise BadELF("can't find LOAD segment")
        
    
    def add_section(self, section, segment=None):
        assert isinstance(section, Custom_Section)
        if segment is not None:
            assert isinstance(segment, Custom_Segment)
            segment.register_section(section)
        
        self.ehdr['e_shnum'] += 1
        self.custom_sections.append(section)
    
    def remove_shdr_entry(self, sh_num):
        ''' remove a section header entry (does not remove/zero out the section's contents)
            the current purpose of this funciton is to repurpose the space consumed by unneeded sections
            to do this we must remove the associated section header entry and do some additional bookkeeping
            @param sh_num: section header number to remove from the section headers
            @note: shdr entries are stored in a list so removing one entry will change subsequent indicies
                    to remove many entires, it is recommended to remove them inreverse order so the indicies 
                    or subsequently removed entries do not change after each removal
            @note: currently unspecified what happens when a section header is removed that is associated with 
                    another section via that section's sh_link or sh_info field
            @note: the section types handled are most likely incomplete
        '''
        # remove the section header entry
        logger.debug("removing section header entry %d", sh_num)
        if len(self.shdrs['entries']) < sh_num:
            logger.warn("Cannot remove section %d: Invalid section number", sh_num)
            return None
        removed_section = self.shdrs['entries'].pop(sh_num)
        
        # make a pass over the remaining section headers, adjusting link/info fields if needed (depends on section type)
        for section in self.shdrs['entries']:
            if section.sh_type == SHT_HASH:
                #sh_link: section header index of the symbol table to which the hash table applies
                if section.sh_link > sh_num:
                    section.sh_link -= 1
            elif section.sh_type == SHT_DYNAMIC:
                #sh_link: section header index of the string table used by entries in the section
                if section.sh_link > sh_num:
                    section.sh_link -= 1
            elif section.sh_type in [SHT_REL, SHT_RELA]:
                #sh_link: section header index of the associated symbol table
                #sh_info: section header index of the section to which the relocation applies
                if section.sh_link > sh_num:
                    section.sh_link -= 1
                if section.sh_info > sh_num:
                    section.sh_info -= 1
            elif section.sh_type in [SHT_SYMTAB, SHT_DYNSYM]:
                #sh_link: section header index of the associated string table
                if section.sh_link > sh_num:
                    section.sh_link -= 1
            elif section.sh_type in [SHT_GNU_versym, SHT_GNU_verdef, SHT_GNU_verneed]:
                #sh_link: section header index that contains the strings referenced by this section
                if section.sh_link > sh_num:
                    section.sh_link -= 1
        
        # update the section header string table index in the ELF header
        if self.ehdr['e_shstrndx'] > sh_num:
            self.ehdr['e_shstrndx'] -= 1
        
        # update the number of section headers in the ELF header
        self.ehdr['e_shnum'] -= 1
                    
        return removed_section
        
    def add_segment(self, segment):
        assert isinstance(segment, Custom_Segment)
        # check for room in program headers for a new entry
        if len(self.phdrs['entries']) < self.phdrs['max_num']:
            self.phdrs['entries'].append(segment)
        else:
            logger.error("Cannot add another section. Not enough room in the program headers to add another segment")
            return None
        self.ehdr['e_phnum'] += 1
        return self.phdrs['entries'][-1]
        
    def dump_shdrs(self):
        ''' Get the section header table which includes all of the original section header entries
            plus all of the entries for the custom sections
        '''
        ret = ''.join(s.dump_entry() for s in self.shdrs['entries'])
        ret += ''.join(s.dump_entry() for s in self.custom_sections)
        return ret
    
    def dump_phdrs(self):
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
            
            #TODO: add sections according to the requested offset (if present)
            #        right now, any requested offset is being ignored
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
            self.ehdr['e_shoff'] = new_sh_offset
            
            logger.info("Appending %d section header entries (%d + %d)", len(self.shdrs['entries']) + len(self.custom_sections),
                        len(self.shdrs['entries']), len(self.custom_sections))
            f.write(self.dump_shdrs())
            
            
            # copy the program headers to the space that was determined in relocate_phdrs
            logger.debug("Writing program headers to offset 0x%x", self.phdrs['base'])
            self.ehdr['e_phoff'] = self.phdrs['base']
            f.seek(self.phdrs['base'])
            
            phdr_bytes = self.dump_phdrs()
            f.write(phdr_bytes)
            
            
            # write the new elf header
            f.seek(0)
            f.write(self.dump_ehdr())
                
            
            # process any patches that were registered for Section objects via section.write()
            #TODO: more elegant solution for this and writing the final ELF in general
            for i, section in enumerate(self.shdrs['entries']):
                for new_bytes, section_offset in section.buffered_writes:
                    logger.debug("Patching in user-defined bytes for section %d", i)
                    file_offset = section.sh_offset + section_offset
                    f.seek(file_offset)
                    f.write(new_bytes)
            
        self._sanity()
        logger.info("finished writing ELF")
    
    ''' don't think we will need this
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
    '''
    
    def addr_to_section(self, addr):
        ''' Returns the section that contains addr or None
        '''
        # NOTE: section bounds check does not include padding if present
        # NOTE: bss sections will return None
        # TODO: check custom sections once offset placement is enforced
        for section in self.shdrs['entries']:
            if section.sh_type == SHT_NOBITS:
                continue
            if section.sh_addr <= addr < section.sh_addr + section.sh_size:
                return section
        return None
    
    def offset_to_section(self, offset):
        ''' Returns the section that contains offset or None
        '''
        # NOTE: section bounds check does not include padding if present
        # NOTE: bss sections will return None
        # TODO: check custom sections once offset placement is enforced
        for section in self.shdrs['entries']:
            if section['sh_type'] == SHT_NOBITS:
                continue
            if section.sh_offset <= offset < section.sh_addr + section.sh_size:
                return section
        return None
    
    def write_to_section(self, section, new_bytes, offset=0):
        if isinstance(section, Section):
            return section.write(new_bytes, offset)
        elif isinstance(section, Custom_Section):
            logger.warn("this API is not available for Custom_Sections. change contents by using section.contents=updated_contents")
        return None
    
    def set_entry_point(self, entry_point):
        self.ehdr['e_entry'] = entry_point
        
    def set_interp(self, new_interp):
        ''' new_interp should be null-terminated
        '''
        interp_section = None
        for segment in self.phdrs['entries']:
            if segment.p_type == PT_INTERP:
                interp_section = self.addr_to_section(segment.p_vaddr)
                break
        if interp_section is not None:
            return self.write_to_section(interp_section, new_interp, 0)
        
        return None
    
    def _sanity(self):
        ''' Help catch illusive bugs
        '''
        if len(self.ehdr) != 14:
            logger.error("ELF header has unexpected number of members - potential bug")
        if len(self.phdrs) != 4:
            logger.error("Program headers have unexpected number of members - potential bug")
        if len(self.shdrs) != 2:
            logger.error("Section headers have unexpected number of members - potential bug")
    
    ''' deprecated -- keep changes in a local copy of the original ELF header
                      and write that out when finished ELF manipulations
    def patch_elf_header(self, f, new_sh_offset, new_ph_offset):
        #TODO: abstract this function
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
    '''

class Section(object):
    ''' The basic section class.
        This class is only to be used to copy the section headers from the original ELF file
        
        User-defined sections must be instanciated via the Custom_Section class
    '''
    def __init__(self, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize, contents):
        
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
        
        self.contents = contents
        self.buffered_writes = []
        
    
    def get_next_offset(self):
        ''' Determines the file offset at which this section will be placed in the ELF 
        '''
        pass
    
    def write(self, new_bytes, offset=0):
        ''' Write new_bytes to section offset
        @note: written only when the ELF is written to disk
        '''
        #TODO: check that the size can fit in this section
        if self.sh_type != SHT_NOBITS:
            if len(new_bytes) <= self.sh_size - offset:
                self.buffered_writes.append((new_bytes, offset))
                return self
        return None
    
    def get_original_bytes(self, offset=None, size=None):
        ''' Returns the original, unmodified size number of bytes at offset
        '''
        if offset is None:
            offset = 0
        if size is None:
            return self.contents[offset:]
        else:
            return self.contents[offset: offset + size]
    
    def get_current_contents(self):
        ''' Returns len number of bytes at offset of the section contents that will be written to disk
            This includes any modifications that have been saved using self.write()
        '''
        current_contents = self.contents
        #TODO: sort by offset and write in one pass
        for new_bytes, offset in self.buffered_writes:
            current_contents = current_contents[0:offset] + new_bytes + current_contents[offset + len(new_bytes):]
        return current_contents
        
    def dump_entry(self):
        return struct.pack("<10i", 
                           self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, 
                           self.sh_offset, self.sh_size, self.sh_link, self.sh_info, 
                           self.sh_addralign, self.sh_entsize)
        
    def __str__(self):
        return "Name: 0x%x, Type: %s, Flags: %s, Addr: 0x%08x, Offset: %s, Size: %s bytes, Link: %s, Info: %s, Align: %d, EntSz: %d" % \
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
                                             0,
                                             contents,
                                             )
        if self.sh_size is None:
            self.sh_size = len(self.contents)
        
        print "Created custom section:"
        print self
    
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
    
    def __str__(self):
        return "Type: 0x%x, Offset: 0x%08x, Vaddr: 0x%08x, Paddr: 0x%08x, Filesize: 0x%08x, Memsize: 0x%08x, Flags: 0x%08x, Align: %d" % \
                (self.p_type, self.p_offset, self.p_vaddr, self.p_paddr, 
                 self.p_filesz, self.p_memsz, self.p_flags, self.p_align)
    
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
        # only makes sense if this segment has sections
        if len(self.sections) > 0:
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


