import logging
import os
import shutil
import struct

from elftools.elf.descriptions import describe_p_type
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_SH_TYPE, ENUM_P_TYPE, ENUM_E_TYPE, ENUM_E_MACHINE, ENUM_E_VERSION

from constants import (SHF_WRITE,
                       SHF_ALLOC,
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


logger = logging.getLogger(__name__)
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(levelname)s   %(module)s.%(funcName)s :: %(message)s'))
logger.addHandler(sh)
logger.propagate = False

PAGESIZE = 0x1000

class BadELF(RuntimeError):
    ''' raised when the ELF cannot be processed by ELFManip
        e.g., unexpected section/segment layout, missing sections/segments
    '''
    pass

class ELFManip(object):
    def __init__(self, in_file, num_adtl_segments=1, unsafe_try_hard=False):
        '''
        @param in_file: Path to the ELF executable
        @param num_adtl_segments: The number of additional segments required
               TODO: explain a bit about this number
        @param unsafe_try_hard: Causes ELFManip to only stop on fatal errors.
                                Unsafe because the result may be broken
        '''
        self.filename = in_file
        self._file = open(self.filename, "rb")
        self.elf = ELFFile(self._file)
        self.num_adtl_segments = num_adtl_segments
        self.unsafe_try_hard = unsafe_try_hard

        # Save architecture in order to change platform-dependent entries in headers 
        self.arch = self.elf.get_machine_arch()
        logger.info("Architecture: %s", self.arch)

        self.image_base = self._get_image_base()
        logger.info("Image base: 0x%08x", self.image_base)


        # TODO: replace custom_sections with functions that interface wth CustomSegment objects inside self.phdrs['entries']
        #      add differentiation between unbacked sections and sections backed by a segment
        self.custom_sections = []

        self.ehdr = self._init_ehdr()
        self.phdrs = self._init_phdrs()
        self.shdrs = self._init_shdrs()

    def _get_image_base(self):
        ''' Find the lowest address of all the loadable segments.
        '''
        base = None
        for segment in self.elf.iter_segments():
            if segment.header.p_type == "PT_LOAD":
                if base is None:
                    base = segment.header.p_vaddr
                elif base > segment.header.p_vaddr:
                    base = segment.header.p_vaddr
        return base

    def _init_phdrs(self):
        ''' Initialize copies of the program headers
        '''
        phdrs = {'base': self.ehdr['e_phoff'],
                 'max_num': self.elf['e_phnum'],
                 'size': self.ehdr['e_phentsize'] * self.ehdr['e_phnum'],
                 'entries': []}
        # copy all the original program headers from the ELF file
        for s in self.elf.iter_segments():
            phdrs['entries'].append(Segment(ENUM_P_TYPE[s['p_type']], s['p_offset'], s['p_vaddr'], s['p_paddr'],
                                            s['p_filesz'], s['p_memsz'], s['p_flags'], s['p_align'], self.arch))
        logger.debug("Copied %d program headers from %s", len(phdrs['entries']), self.filename)
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
                                            contents, self.arch))
        logger.debug("Copied %d section headers from %s", len(shdrs['entries']), self.filename)
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
        # Set size for platform-dependent entries.  Default value is a 32-bit int.
        size = 'Q' if self.arch == 'x64' else 'I'
        return self.ehdr['e_ident'] + struct.pack("<HHI%s%s%sIHHHHHH" % (size,size,size),
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

    def relocate_phdrs(self, custom_offset=None, new_size=None, segment=None, use_methods=None):
        '''
        Attempts to find a new location for the program headers to reside in the ELF image.
        In theory, you should be able to place the program headers anywhere in the image. The
        loader has the requirement that it be placed in a PT_LOAD segment. However, in testing,
        if the new address is 'too far' (one page?) away from the image base, it will fail an
        assertion in the loader which will terminate the program.

        If an explicit custom_offset is given, the new program headers will be placed there -
        no questions asked. Otherwise, a series of methods will be executed in attempt to find a
        suitable location.

        @param custom_offset: The file offset to move the new phdrs
        @note: new_size should ideally be a multiple of e_phentsize (not enforced)
        @return: location of the new phdrs (could be the original location)
        '''
        if custom_offset is not None:
            if new_size is None:
                logger.warn("You must specify the size of the relocated program headers")
                return None

            logger.debug("Moving program headers to offset 0x%08x" % custom_offset)
            self._update_phdr_entry(custom_offset, new_size, segment)
            return self.phdrs['base']

        logger.info("Finding space to relocate the program headers...")
        if use_methods is None:
            use_methods = [self._phdr_hack1, self._phdr_hack2, self._phdr_hack3]
        for method in use_methods:
            if method():
                return self.phdrs['base']
        else:
            logger.warn("All methods failed")
        return None

    def _phdr_hack1(self):
        '''
        Check if there is enough space in the gap between 'AX' and 'WA' segments.
        These segments, if they exist, will necessarily be mapped to different pages.
        If there is sufficient space after the 'AX' segment and before the 'WA' segment,
        we can place the new program headers there.
        '''
        logger.debug("Trying method 1...")

        section_before_padding = None
        section_after_padding = None

        # TODO: generalize this to handle unordered section header entries (legal?)
        # TODO: ^ can we just use the program headers???
        for section in self.elf.iter_sections():
            if section['sh_flags'] & SHF_WRITE:
                section_after_padding = section
                break
            else:
                section_before_padding = section

        if section_before_padding is None:
            logger.error("Cannot relocate the program headers.")
            raise BadELF("ELF has no sections?")
        elif section_after_padding is None:
            logger.error("Cannot relocate the program headers.")
            raise BadELF("ELF has no writable section?")

        logger.debug("Sections on either side of the segment padding: [%s, %s]", section_before_padding.name, section_after_padding.name)

        free_space_start = section_before_padding['sh_offset'] + section_before_padding['sh_size']
        free_space_size = section_after_padding['sh_offset'] - free_space_start

        logger.debug("Found 0x%x bytes of padding at offset 0x%x. Thats enough for %d entries of size %d each.",
                     free_space_size, free_space_start, free_space_size / self.ehdr['e_phentsize'], self.ehdr['e_phentsize'])

        minimum_required_space = (self.ehdr['e_phnum'] + self.num_adtl_segments) * self.ehdr['e_phentsize']
        if free_space_size >= minimum_required_space:
            logger.debug("Found enough space to move the program headers!")

            # check that this space is actually empty (as it should be)
            if not self.unsafe_try_hard:
                empty = True
                self._file.seek(section_before_padding['sh_offset'] + section_before_padding['sh_size'])
                for b in self._file.read(free_space_size):
                    if b != "\x00":
                        empty = False
                if not empty:
                    # not sure why this would ever happen in a "normal" compiler-generated binary
                    raise BadELF("Padding is not empty. Use unsafe_try_hard if you want to proceed.")

            self._update_phdr_entry(free_space_start, free_space_size)
            return True
        logger.info("Method 1 failed - there is not enough space between segments to fit the new program headers")
        return False

    def _phdr_hack2(self):
        '''
        Try to repurpose the GNU_STACK entry. I.e., delete it, freeing room for one additional entry.
        At one point I was convinced that in most cases, this entry is not needed. Could be wrong.
        '''
        logger.info("Trying method 2...")
        if self.num_adtl_segments != 1:
            logger.info("Method 2 does not apply: Would only provide one additional segment")
            return False

        for idx, segment in enumerate(self.elf.iter_segments()):
            # TODO: why are we not calling self._update_phdr_entry like in Method 1??
            if describe_p_type(segment['p_type']) == "GNU_STACK":
                # keep the old base and max number of entries
                self.phdrs['base'] = self.ehdr['e_phoff']
                self.phdrs['max_num'] = len(self.phdrs['entries'])
                # remove this entry, freeing up room for one user defined entry
                logger.debug("removing GNU_STACK pdhr entry")
                del self.phdrs['entries'][idx]
                self.ehdr['e_phnum'] -= 1

                # assert describe_p_type(gnu_stack_entry.p_type) == "GNU_STACK"
                logger.info("should have room to add one section/segment")
                return True
        else:
            logger.info("Method 2 does not apply: No GNU_STACK entry")
        return False


    def _phdr_hack3(self):
        '''
        Try to remove and move some sections to make room for the new program headers.
        The main idea is that the first few sections should be something like: [NULL, interp, NOTE1, NOTE2, ...].
        The NOTE* sections are unneeded and can be removed. The NULL and interp sections are needed but can
        be shifted over, overriting part of the old NOTE* section(s). This effectively frees up space just
        after the old program headers, allowing for a few more (usually 2) entries to be added.
        '''
        logger.info("Trying method 3...")
        # move .interp section AND remove any following .note.* sections
        interp_index = 1  # hardcoded and expected location of the .interp section header entry
        shstrtab_offset = self.shdrs['entries'][self.ehdr['e_shstrndx']].sh_offset
        str_offset = self.shdrs['entries'][interp_index].sh_name
        self._file.seek(shstrtab_offset + str_offset)
        name = self._file.read(7)

        if name != '.interp':
            logger.info("Method 3 failed: Unexpected section order.")
            return False

        # find the last NOTE section in the group of contiguous NOTE sections immediately following .interp
        last_note_section = None
        for idx, section in enumerate(self.shdrs['entries']):
            if idx in range(interp_index + 1):
                # skip to the section after .interp
                continue
            if section.sh_type == SHT_NOTE:
                last_note_section = idx
            else:
                break
        if last_note_section is None:
            logger.info("Method 3 failed: There are no NOTE sections to remove")
            # TODO: if no NOTE sections, ability to move .interp (if doing so would satisfy the requested num of segments) would be nice
            #       also, if you need just a few more bytes you can write a new hack that renames the interpreter to a short name
            #       like /l and symlink it to the old value
            return False

        num_freed_sections = last_note_section - interp_index
        freed_space = 0
        for section in self.shdrs['entries'][interp_index + 1: last_note_section + 1]:
            freed_space += section.sh_size

        num_new_phdr_entries = freed_space / self.ehdr['e_phentsize']
        if num_new_phdr_entries < self.num_adtl_segments:
            logger.warn("Method 3 failed: Not enough space for %d additional phdrs", self.num_adtl_segments)
            return False

        logger.info("Method 3 success!")
        logger.debug("removing shdr entries for %d NOTE sections", num_freed_sections)
        logger.debug("resulted in room for %d additional program headers", num_new_phdr_entries)

        # move shdrs 0 and 1 (NULL, .interp) to overwrite shdrs last_note_section-1 and last_note_section, respectively
        self.shdrs['entries'][last_note_section - 1] = self.shdrs['entries'][0]
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
                break

        # free up the added space by updating the elf header
        self.ehdr['e_shoff'] += num_freed_sections * self.ehdr['e_shentsize']

        self._update_phdr_entry(self.phdrs['base'], self.phdrs['size'] + freed_space)
        return True

    def _update_phdr_entry(self, new_base, max_size, segment=None):
        ''' Update the PHDR entry to match the new location of the program headers
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
                if self.arch == 'x64':
                    p.p_filesz = len(self.phdrs['entries']) * 56  # 56 bytes each for 64-bit
                else:
                    p.p_filesz = len(self.phdrs['entries']) * 32  # 32 bytes each for 32-bit
                p.p_memsz = p.p_filesz

        if segment is not None:
            # now that the phdrs have sufficient room, we can add the user supplied segment
            logger.debug("Added user defined segment backing the new program headers")
            self.add_segment(segment)

        # following assumes that the only time we need to what the segment entry is when the base changed
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
                    segment.p_memsz = segment.p_filesz
                    break

            if not found:
                logger.warning("problem finding LOAD segment containing new phdr location")
                #raise BadELF("can't find LOAD segment")

    def add_section(self, section, segment=None):
        assert isinstance(section, CustomSection)
        section.arch = self.arch # Override initial value so that custom section's arch matches the binary
        if segment is not None:
            assert isinstance(segment, CustomSegment)
            segment.register_section(section)

        self.ehdr['e_shnum'] += 1
        self.custom_sections.append(section)

    def remove_shdr_entry(self, sh_num):
        ''' Remove a section header entry (does not remove/zero out the section's contents).
            The current purpose of this funciton is to repurpose the space consumed by unneeded sections.
            To do this we must remove the associated section header entry and do some additional bookkeeping.
            @param sh_num: section header number to remove from the section headers
            @note: shdr entries are stored in a list so removing one entry will change subsequent indicies
                    to remove many entires, it is recommended to remove them inreverse order so the indicies
                    or subsequently removed entries do not change after each removal
            @note: the section types handled are most likely incomplete
        '''
        logger.debug("Removing section header entry %d", sh_num)
        if len(self.shdrs['entries']) < sh_num:
            logger.warn("Cannot remove section %d: Invalid section number", sh_num)
            return None
        removed_section = self.shdrs['entries'].pop(sh_num)

        # make a pass over the remaining section headers, adjusting link/info fields if needed (depends on section type)
        for section in self.shdrs['entries']:
            if section.sh_type == SHT_HASH:
                # sh_link: section header index of the symbol table to which the hash table applies
                if section.sh_link > sh_num:
                    section.sh_link -= 1
            elif section.sh_type == SHT_DYNAMIC:
                # sh_link: section header index of the string table used by entries in the section
                if section.sh_link > sh_num:
                    section.sh_link -= 1
            elif section.sh_type in [SHT_REL, SHT_RELA]:
                # sh_link: section header index of the associated symbol table
                # sh_info: section header index of the section to which the relocation applies
                if section.sh_link > sh_num:
                    section.sh_link -= 1
                if section.sh_info > sh_num:
                    section.sh_info -= 1
            elif section.sh_type in [SHT_SYMTAB, SHT_DYNSYM]:
                # sh_link: section header index of the associated string table
                if section.sh_link > sh_num:
                    section.sh_link -= 1
            elif section.sh_type in [SHT_GNU_versym, SHT_GNU_verdef, SHT_GNU_verneed]:
                # sh_link: section header index that contains the strings referenced by this section
                if section.sh_link > sh_num:
                    section.sh_link -= 1

        # update the section header string table index in the ELF header
        if self.ehdr['e_shstrndx'] > sh_num:
            self.ehdr['e_shstrndx'] -= 1

        # update the number of section headers in the ELF header
        self.ehdr['e_shnum'] -= 1

        return removed_section

    def add_segment(self, segment):
        ''' Registers a segment to be added to the new ELF when it is written
        @param segment: The CustomSegment instance to add
        @return: Number of segment slots that are still available or None if could not add segment
        '''
        if not isinstance(segment, CustomSegment):
            raise TypeError("Passed non-CustomSegment to add_segment")
        segment.arch = self.arch # Override initial value so that custom segment's arch matches the binary

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
            if isinstance(phdr, CustomSegment):
                phdr.finalize()
        return ''.join(p.dump_entry() for p in self.phdrs['entries'])

    def write_new_elf(self, outfile):
        if outfile == self.filename:
            logger.error("Must specify a different file destination than the original ELF")
            return

        logger.info("Writing new ELF: %s", outfile)
        # copy the entire file first
        shutil.copy(self.filename, outfile)
        with open(outfile, "r+b") as f:
            # append all the section contents, patching in the sh_addr and sh_offset fields as they are concretized
            f.seek(0, os.SEEK_END)

            # TODO: add sections according to the requested offset (if present)
            #        right now, any requested offset is being ignored
            added_segment = False
            for phdr in self.phdrs['entries']:
                if not isinstance(phdr, CustomSegment):
                    continue
                added_segment = True
                for section in phdr.sections:

                    if section.mapped_by != phdr:
                        # this section is already mapped by a *different* segment
                        # therefore, we need to skip copying these bytes to the ELF

                        # TODO: check that the segment mapping this section is a LOAD type
                        #        but then this depends on the use case.
                        #        maybe create a more general API?

                        # only handle one section <--> segment mapping
                        assert len(section.mapped_by.sections) == 1

                        # assert section.mapped_by.sections[0].sh_offset is not None
                        # this is always None. don't remember where it is adjusted before being written to the ELF
                        # but it is being taken care of somewhere
                        # section.sh_offset = section.mapped_by.sections[0].sh_offset

                    else:
                        pad_to_modulus(f, PAGESIZE)
                        pad_to_modulus(f, PAGESIZE, pad_if_aligned=True)
                        section_offset = f.tell()
                        f.write(section.contents)

                        section.sh_offset = section_offset

            # If any custom *segments* were added, copy the original + custom *sections* to EOF
            if added_segment:
                pad_to_modulus(f, 0x10)

                new_sh_offset = f.tell()
                self.ehdr['e_shoff'] = new_sh_offset

                logger.info("Appending %d section header entries (%d + %d)", len(self.shdrs['entries']) + len(self.custom_sections),
                            len(self.shdrs['entries']), len(self.custom_sections))
                f.write(self.dump_shdrs())


                # Now do the same for the segments
                logger.debug("Writing program headers to offset 0x%x", self.phdrs['base'])
                self.ehdr['e_phoff'] = self.phdrs['base']
                f.seek(self.phdrs['base'])

                phdr_bytes = self.dump_phdrs()
                f.write(phdr_bytes)


            # Copy the (possibly modified) ELF header even if no custom segments were added
            f.seek(0)
            f.write(self.dump_ehdr())


            # process any patches that were registered for Section objects via section.write()
            # TODO: more elegant solution for this and writing the final ELF in general
            for i, section in enumerate(self.shdrs['entries']):
                for new_bytes, section_offset in section.buffered_writes:
                    logger.debug("Patching in user-defined bytes for section %d (%s)", i, section.sh_name)
                    file_offset = section.sh_offset + section_offset
                    f.seek(file_offset)
                    f.write(new_bytes)

        logger.info("finished writing ELF")

    def addr_to_section(self, addr):
        ''' Returns the section that contains addr or None
        '''
        for section in self.shdrs['entries']:
            if section.sh_type == SHT_NOBITS:
                continue
            if section.sh_addr <= addr < section.sh_addr + section.sh_size:
                return section
        return None

    def offset_to_section(self, offset):
        ''' Returns the section that contains offset or None
        '''
        for section in self.shdrs['entries']:
            if section['sh_type'] == SHT_NOBITS:
                continue
            if section.sh_offset <= offset < section.sh_addr + section.sh_size:
                return section
        return None

    def write_to_section(self, section, new_bytes, offset=0):
        if isinstance(section, Section):
            return section.write(new_bytes, offset)
        elif isinstance(section, CustomSection):
            logger.warn("this API is not available for CustomSections. change contents by using section.contents=updated_contents")
        return None

    def set_entry_point(self, entry_point):
        self.ehdr['e_entry'] = entry_point

    def set_interp(self, new_interp):
        ''' new_interp should be null-terminated
        '''
        for segment in self.phdrs['entries']:
            if segment.p_type == PT_INTERP:
                interp_section = self.addr_to_section(segment.p_vaddr)
                return self.write_to_section(interp_section, new_interp)
        return None

class Section(object):
    ''' The basic section class.
        This class is only to be used to copy the section headers from the original ELF file

        User-defined sections must be instanciated via the CustomSection class
    '''
    def __init__(self, sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize, contents, arch):

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

        self.segment = None  # defined when a segment is created for this section

        self.contents = contents
        self.buffered_writes = []

        self.arch = arch

    def write(self, new_bytes, offset=0):
        ''' Write new_bytes to section offset
        @note: written only when the ELF is written to disk
        '''
        # TODO: check that the size can fit in this section
        if self.sh_type != SHT_NOBITS:
            if len(new_bytes) <= self.sh_size - offset:
                self.buffered_writes.append((new_bytes, offset))
                return True
        return False

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
        # TODO: sort by offset and write in one pass
        for new_bytes, offset in self.buffered_writes:
            current_contents = current_contents[0:offset] + new_bytes + current_contents[offset + len(new_bytes):]
        return current_contents

    def dump_entry(self):
        # Set size for platform-dependent entries.  Default value is a 32-bit int.
        size = 'Q' if self.arch == 'x64' else 'I'
        return struct.pack("<2I4%s2I2%s" % (size,size),
                           self.sh_name, self.sh_type, self.sh_flags, self.sh_addr,
                           self.sh_offset, self.sh_size, self.sh_link, self.sh_info,
                           self.sh_addralign, self.sh_entsize)

    def __str__(self):
        return "Name: 0x%x, Type: %s, Flags: %s, Addr: 0x%08x, Offset: %s, Size: %s bytes, Link: %s, Info: %s, Align: %d, EntSz: %d" % \
                (self.sh_name, self.sh_type, self.sh_flags, self.sh_addr,
                 self.sh_offset, self.sh_size, self.sh_link, self.sh_info,
                 self.sh_addralign, self.sh_entsize)


class CustomSection(Section):
    def __init__(self, contents='', name=0x1f, sh_type=SHT_PROGBITS, sh_flags=SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR, sh_addr=None, sh_addralign=0x10, arch='x86'):
        '''
        @param contents: contents of the section as a string
        @param name: offset into the section header string table; custom name is not implemented
        '''
        super(self.__class__, self).__init__(name,
                                             sh_type,
                                             sh_flags,
                                             sh_addr,
                                             None,
                                             None,
                                             SHN_UNDEF,
                                             0,
                                             sh_addralign,
                                             0,
                                             contents,
                                             arch
                                            )
        if self.sh_size is None:
            self.sh_size = len(self.contents)

        self.mapped_by = None  # the segment that this section belongs
                               # used when the same section is referenced by more than one segment

    def is_defined(self):
        for attr in [self.sh_name, self.sh_type, self.sh_flags, self.sh_addr, self.sh_offset, self.sh_size,
                     self.sh_link, self.sh_info, self.sh_addralign, self.sh_entsize]:
            if attr is None:
                return False
        return True

class Segment(object):
    def __init__(self, p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align, arch):
        self.p_type = p_type
        self.p_offset = p_offset
        self.p_vaddr = p_vaddr
        self.p_paddr = p_paddr  # unspecified contents by System V
        self.p_filesz = p_filesz
        self.p_memsz = p_memsz
        self.p_flags = p_flags
        self.p_align = p_align
        self.arch = arch

    def __str__(self):
        return "Type: 0x%x, Offset: 0x%08x, Vaddr: 0x%08x, Paddr: 0x%08x, Filesize: 0x%08x, Memsize: 0x%08x, Flags: 0x%08x, Align: %d" % \
                (self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
                 self.p_filesz, self.p_memsz, self.p_flags, self.p_align)

    def dump_entry(self):
        # 64-bit binaries change the location of p_flags, so segments differ more significantly between
        # x64 and x86 binaries than sections.
        if self.arch == 'x64':
            return struct.pack("<2I6Q",
                           self.p_type, self.p_flags, self.p_offset, self.p_vaddr, self.p_paddr,
                           self.p_filesz, self.p_memsz, self.p_align)
        else:
            return struct.pack("<8I",
                           self.p_type, self.p_offset, self.p_vaddr, self.p_paddr,
                           self.p_filesz, self.p_memsz, self.p_flags, self.p_align)

class CustomSegment(Segment):
    def __init__(self, p_type, p_offset=None, p_vaddr=None, p_paddr=None, p_filesz=None, p_memsz=None, p_flags=None, p_align=0x1000, arch='x86'):
        '''
        Just like a Segment except we need to do special things to make sure that the segments are mapped correctly
        '''
        super(self.__class__, self).__init__(p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align, arch)

        self.sections = []

    def register_section(self, section):
        '''
        Associate section with this segment
        '''
        if not isinstance(section, CustomSection):
            raise TypeError("section must be a CustomSection instance")
        self.sections.append(section)
        section.mapped_by = self

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
        '''
        Call after all sections have been added to this segment and those section's properties have been finalized.
        This will attempt to fill in all the correct phdr values with respect to the sections that have been registered.
        '''
        for section in self.sections:
            if not section.is_defined():
                logger.error("Section to be loaded at 0x%x is not fully initialized!" % section.sh_addr)
                return
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
    if not pad_if_aligned and current % modulus == 0:
        return
    if padding_bytes == '':
        return

    padding_len = modulus - (current % modulus)
    logger.debug("padding EOF with %d null bytes", padding_len)
    f.write(padding_bytes * (padding_len / len(padding_bytes)) + padding_bytes[:padding_len % len(padding_bytes)])
