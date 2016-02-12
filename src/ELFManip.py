from Constants import *

import struct
import binascii
import os

import logging
logger = logging.getLogger("ELFManip")
logger.setLevel(logging.DEBUG)
sh = logging.StreamHandler()
sh.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))
logger.addHandler(sh)
logger.propagate = False # turn off propagation to root handler prevents duplicate log entries

#import idc, idautils
from __builtin__ import bytearray
#from idc import SEGATTR_ALIGN

import pprint
pp = pprint.PrettyPrinter(indent=4)

#output_base_path = "Z:\\delinker-test\\output"
LOG_LEVEL = 4

# order of section headers as they should appear in table of section headers
section_header_order = ['.text', '.data', '.bss', '.rodata', '.rel.text', '.rel.data', '.rel.rodata', '.shstrtab', '.symtab', '.strtab']

persistent_sections = ['.text', '.data', '.bss'] # sections that should (must?) be present in all object files even if size is 0

# Comment section... 
COMMENT = "Produced by Delinker"
COMMENT_HEX = "00"+binascii.hexlify(COMMENT)+"00" # start and end with null byte


class Logger:
	def __init__(self, log_level):
		self.log_level=log_level
	
	def error(self, msg):
		if self.log_level >= 1:
			print "[ERROR] - %s" % msg
			
	def warn(self, msg):
		if self.log_level >= 2:
			print "[WARNING] - %s" % msg
	
	def info(self, msg):
		if self.log_level >= 3:
			print "[INFO] - %s" % msg
			
	def debug(self, msg):
		if self.log_level >= 4:
			print "[DEBUG] - %s" % msg
	
class ELF:
	
	def __init__(self, obj_filename, log_level=4):
		self.logger = Logger(log_level)
		self.logger.info("Initializing ELF object '%s'" % obj_filename)
		self.obj_filename = obj_filename
		self.elfhdr = ''
		
		self.shdr_table = list()
		self.sections_present = ['.text', '.data', '.bss', '.rodata', '.rel.text', '.rel.data', '.rel.rodata', '.shstrtab', '.symtab', '.strtab'] # remove sections individually if not needed
		self.symbol_table = list()
		self.symbol_table_index = list() # dont think we need this
		
		self.str_table = list()
		self.strtab_dict = dict()
		self.strtab_offset = 0 # current size of string table - use to set offsets into strtab as entries are added
		self.symtab_dict = dict() # key = symbol name, value = index into symbol table
		
		# dictionary to hold hex repr of each section
		self.sections_hex = {'.text': '','.data': '','.bss': '','.rodata': '',
						'.shstrtab': '','.symtab': '','.strtab': '','.rel.text': '','.rel.data': '','.rel.rodata': '',
						}
		
		# Section headers for each section, with default values.
		# the default NULL section at index 0 is manually copied at the beginning of BuildSectionHeaders
		# names are now computed dynamically in BuildSectionHeaders since all sections may not be needed
		# link and info are now computed dynamically in BuildSectionHeaders for all rel sections and symtab
		text_shdr =			{'name':0, 'type':SHT_PROGBITS, 'flags':SHF_ALLOC|SHF_EXECINSTR, 	'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':4, 'entsize':0}
		rel_text_shdr =		{'name':0, 'type':SHT_REL, 		'flags':0, 							'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':4, 'entsize':RELOCTAB_ENTRY_SIZE}
		data_shdr =			{'name':0, 'type':SHT_PROGBITS, 'flags':SHF_WRITE|SHF_ALLOC, 		'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':4, 'entsize':0}
		rel_data_shdr =		{'name':0, 'type':SHT_REL, 		'flags':0, 							'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':4, 'entsize':RELOCTAB_ENTRY_SIZE}
		bss_shdr =			{'name':0, 'type':SHT_NOBITS, 	'flags':SHF_WRITE|SHF_ALLOC, 		'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':4, 'entsize':0}
		rodata_shdr =		{'name':0, 'type':SHT_PROGBITS, 'flags':SHF_ALLOC, 					'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':4, 'entsize':0}
		rel_rodata_shdr =	{'name':0, 'type':SHT_REL, 		'flags':0, 							'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':4, 'entsize':RELOCTAB_ENTRY_SIZE}
		shstrtab_shdr =		{'name':0, 'type':SHT_STRTAB, 	'flags':0, 							'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':1, 'entsize':0}
		symtab_shdr =		{'name':0, 'type':SHT_SYMTAB, 	'flags':0, 							'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':4, 'entsize':SYMTAB_ENTRY_SIZE}
		strtab_shdr =		{'name':0, 'type':SHT_STRTAB, 	'flags':0, 							'addr':0, 'offset':0, 'size':0, 'link':0, 'info':0, 'addralign':1, 'entsize':0}
		
		# Section header table dictionary
		self.shdr_dict = {'.text':text_shdr, '.rel.text':rel_text_shdr,
					 '.data':data_shdr, '.rel.data':rel_data_shdr,
					 '.bss':bss_shdr, '.rodata':rodata_shdr,
					 '.rel.rodata':rel_rodata_shdr, 
					 '.shstrtab':shstrtab_shdr,
					 '.symtab':symtab_shdr, '.strtab':strtab_shdr
			}
				
	
	def BuildElfHeader(self):
		''' Builds the header for the ELF file type.
			@note: The following entries should need to be calculated (not hardcoded) for each ELF file:
				shoff, shnum, shstrndx
			
		'''
		'''
		typedef struct elf32_hdr{
		  unsigned char e_ident[EI_NIDENT];
		  Elf32_Half	e_type;
		  Elf32_Half	e_machine;
		  Elf32_Word	e_version;
		  Elf32_Addr	e_entry;  /* Entry point */
		  Elf32_Off	 e_phoff;
		  Elf32_Off	 e_shoff;
		  Elf32_Word	e_flags;
		  Elf32_Half	e_ehsize;
		  Elf32_Half	e_phentsize;
		  Elf32_Half	e_phnum;
		  Elf32_Half	e_shentsize;
		  Elf32_Half	e_shnum;
		  Elf32_Half	e_shstrndx;
		} Elf32_Ehdr;
		'''
		
		# Define all of the fields
		magic = "7f454c46010101000000000000000000"
		elf_type = 1 				# relocatable file
		machine = 3 				# Intel 80386
		version = 1 				# current version
		entry = 0 					# no entry point for relocatable files
		phoff = 0 					# offset of program headers (0 for relocatable files)
		shoff = 0 					# offset of section header (0 for now -- must be patched with real value when writing ELF file)
		flags = 0
		ehsize = ELFHDR_SIZE 		# size of this header
		phentsize = 0 				# size of program headers (0 for relocatable files)
		phnum = 0 					# number of program headers (0 for relocatable files)
		shentsize = SHDR_ENTRY_SIZE # size of each section header entry
		
		shnum = 0 					# number of section headers -- must be patched in once known
		shstrndx = 0 				# section header string table index -- must be patched in once known
		
		header = struct.pack("hhIIIIIhhhhhh", elf_type, machine, version, entry, phoff, shoff, flags, ehsize, phentsize, phnum, shentsize, shnum, shstrndx)
		self.elfhdr = magic + header.encode('hex')
	
	
	def SetSHDependencies(self, sections):
		''' Determines which sections will be present in the final ELF and sets the corresponding sections_hex['.shstrtab']
			
			@param sections: dictionary of sections with section info
			@todo: this function does too much (see note below)
			@note: sets sections_present; shdr_dict['.shstrtab']['size']; sections_hex['.shstrtab']
		'''
		self.logger.debug("Setting sections_present and sections_hex['.shstrtab']")
		
		#TODO: unslopify
		# remove unused sections from self.sections_present
		for section_name in section_header_order:
			s = sections[section_name]
			if section_name == '.shstrtab':
				continue
			if ((s['size'] == 0) and (section_name not in persistent_sections)):
				# remove from sections_present
				self.logger.debug("NOT adding section %s: name 0x%x, size 0x%x" % (section_name, s['name'], s['size']))
				if section_name in self.sections_present:
					self.sections_present.remove(section_name)
				
		self.logger.debug("sections to be added: %s" % self.sections_present)
		
		# now that we know what sections are present we can set the size of .shstrtab
		self.shdr_dict['.shstrtab']['size'] = sum(len(section)+1 for section in self.sections_present)+1 # +1 for each null char (initial and terminators)
		
		# set the initial section header string table values (necessarily starts with null string representing null section)
		self.sections_hex['.shstrtab'] = "00"
		shstrtab_size = len(self.sections_hex['.shstrtab'])/2 # used to set the offset into the shstrtab (name) of sections as they are added
		
		#now that all of the fields in shdr_dict (except 'name's) are known, loop through again setting names
		# TODO: this can be simplified now that sections_present starts with all sections
		for section_name in section_header_order:
			s = sections[section_name]
			#if section_name in self.sections_present:
			if ((s['size'] != 0) or (section_name in persistent_sections)):
				# Add section name to section header string table
				self.sections_hex['.shstrtab'] += section_name.encode('hex') + "00"
				s['name'] = shstrtab_size # set index into shstrtab
				assert len(self.sections_hex['.shstrtab']) % 2 == 0
				shstrtab_size = len(self.sections_hex['.shstrtab'])/2 # update size
				
	
	def BuildSectionHeaders(self, sections):
		''' Sets self.shdr_table (section header table) and adds sections to self.sections_present if needed
			
			@param sections: dictionary of section headers with info on each
			@note: section header table alignment is 4 bytes
		'''
		
		'''	
		typedef struct elf32_shdr {
			Elf32_Word	sh_name;	  offset into section header string table
			Elf32_Word	sh_type;	  
			Elf32_Word	sh_flags;	 
			Elf32_Addr	sh_addr;	  0 for our purposes
			Elf32_Off	 sh_offset;	byte offset from beginning of file to first byte in this section
			Elf32_Word	sh_size;	  section size in bytes
			Elf32_Word	sh_link;	  section header table index link
			Elf32_Word	sh_info;	  
			Elf32_Word	sh_addralign; 0 and 1 mean no alignment constraints
			Elf32_Word	sh_entsize;   size of fixed size entries if section is a table or 0 if N/A to this section
		} Elf32_Shdr;
		'''
		def GetSymTabInfoField():
			''' Returns the info field for the symtab sh entry
				This value must be one greater than the symbol table index of the last local symbol (binding STB_LOCAL)
			'''
			index = 0
			for symbol in self.symbol_table:
				if self.GetSTBind(symbol) != STB_LOCAL:
					break
				index += 1
			if index == len(self.symbol_table):
				# all symbols have STB_LOCAL binding (likely an error)
				''' this was here before sound delinker when it was assumed to be nearly impossible for an object file to reference no symbols
					but this is exactly what data.o does
				'''
				#self.logger.warn("Cannot determine info field for symtab sh entry")
				pass
				
			return index
		
		self.logger.debug("Building section headers")
		assert self.shdr_table == [] # must start with empty table
		
		# Manually add first section header entry (mandatory null entry)
		first_entry_hex = struct.pack("IIIIIIIIII", 0,0,0,0,0,0,0,0,0,0).encode('hex')
		self.shdr_table.append(first_entry_hex)

		#now that all of the fields in shdr_dict (except 'name's) are known, loop through again setting names and building shdr_hex string
		for section_name in section_header_order:
			s = sections[section_name]
			#if section_name in self.sections_present:
			if ((s['size'] != 0) or (section_name in persistent_sections)):
				if section_name.startswith('.rel.'):
					# set the link and info fields
					s['link'] = self.sections_present.index('.symtab') + 1 # sh index to .strtab,
					s['info'] = self.sections_present.index(section_name[len('.rel'):]) + 1 # sh index to parent section
				elif section_name == '.symtab':
					# set the link and info fields
					s['link'] = self.sections_present.index('.strtab') + 1 # sh index to .strtab
					s['info'] = GetSymTabInfoField() # symtab index one greater than the last local symbol (binding STB_LOCAL)
					
				# Add section entry to section header table
				#self.logger.debug("Adding section %s:\t name 0x%x, offset 0x%x, size 0x%x" % (section_name, s['name'], s['offset'], s['size']))
				shdr_hex = struct.pack("IIIIIIIIII", s['name'], s['type'], s['flags'], s['addr'], s['offset'], s['size'], s['link'], s['info'], s['addralign'], s['entsize']).encode('hex')
				self.shdr_table.append(shdr_hex)
	
		
	def GetSTBind(self, symbol):
		''' Determines the bind field of symbol
			@param param: symbol
			@return: binding for symbol
		'''
		
		fields = struct.unpack('IIIBBH', symbol.decode('hex'))
		st_bind, _ = self.ParseInfoByte(fields[3])
		return st_bind
	
	def GetSTInfo(self, st_bind, st_type):
		''' Computes the info byte for a symbol table entry
			@param st_bind: symbol binding
			@param st_type: symbol type
			@return: info byte
		'''
		#define ELF32_ST_BIND(i)	((i)>>4)	0=local, 1=global, 2=weak, [13-15]=processor specific
		#define ELF32_ST_TYPE(i)	((i)&0xf)   0=notype, 1=data object (Ex: variable, array, etc), 2=func, 3=section (exist for relocation), 4=file, [13-15]=processor-specific
		#define ELF32_ST_INFO(b,t)  (((b)<<4)+((t)&0xf))
		return (st_bind << 4) + (st_type & 0xf)
		
	def ParseInfoByte(self, st_info):
		''' Returns the tuple (bind, type) of a symbol's info field
			@param st_info: symbol's info
			@return: symbol binding and type
		'''
		return (st_info >> 4, st_info & 0xf)
	
	def AddRelocEntry(self, reloc_offset, rel_type, rel_section, symbol_name, symbol_index_test):
		'''
			@param reloc_offset: integer address of the operand that needs relocation
			@param rel_type: type of reference (1=absolute [R_386_32], 2=indirect [R_386_PC32])
			@param rel_section: string section name that the reloc applies to
			@param symbol_name: name of the corresponding symbol that should be in the symbol table
			@param symbol_index_test: WE SOULD GET RID OF THIS... we are getting the correct value in this function, no need to pass it
			
			@todo: remove symbol_index_test
		'''
		assert rel_type in [R_386_32, R_386_PC32]
		logger.info("Adding relocation for symbol %s at offset 0x%08x in section %s" % (symbol_name, reloc_offset, rel_section))
		
		
		if symbol_name not in self.strtab_dict:
			self.logger.error("%s not found in string table" % symbol_name)
			exit("fix error")
		
		#TODO: abstract the following to a class fucntion
		# Get the symbol index (offset into string table)
		symbol_index = -1 # should stand out when encoded as unsigned int
		for i in range(len(self.symbol_table_index)):
			if self.symbol_table_index[i] == symbol_name:
				#self.logger.debug("Found symbol string at index %d in symbol table" % i)
				symbol_index = i
				break
		
		assert symbol_index == symbol_index_test # test to see if we need to keep the look up dict or just pass the value

		#FIXME: why is the entry being packed with padding??? furthermore, why is there no endianness specified?
		#		this cannot be right... check the ELF spec also, use the functions to convert b/w to and from INFO word
		relocation_entry_hex = struct.pack('IBBxx', reloc_offset, rel_type, symbol_index).encode('hex')

		self.logger.debug("Relocation for symbol %s: %s" % (symbol_name, relocation_entry_hex))
		
		#TODO: we really should be just creating "relocation entry objects"
		#		upon Writing the ELF file (specifically this section) iterate over the objects, writing the bytes
		if rel_section == '.text':
			self.sections_hex['.rel' + rel_section] += relocation_entry_hex
			"""
			self.reloc_text.append(relocation_entry_hex)
			self.shdr_dict['.rel.text']['size'] += len(relocation_entry_hex)/2
		elif rel_section == '.data':
			self.reloc_data.append(relocation_entry_hex)
			self.shdr_dict['.rel.data']['size'] += len(relocation_entry_hex)/2
		elif rel_section == '.rodata':
			self.reloc_rodata.append(relocation_entry_hex)
			self.shdr_dict['.rel.rodata']['size'] += len(relocation_entry_hex)/2
			"""
		else:
			exit("bad argument to AddRelocEntry")
		
	def PrintStringTable(self):
		for s in self.str_table:
			print "\t%s" % repr((s.decode('hex')))
			
	def AddToStringTable(self, name):
		''' Adds string name to the string table
			@param name: string name
		'''
		if name not in self.strtab_dict:
			self.logger.debug("\tAdding '%s' to string table at offset %d" % (name, self.strtab_offset))
			name = str(name) # cast to str if not already (o/w encode and len will fail)
			self.str_table.append(name.encode('hex') + "00")
			self.strtab_dict[name] = self.strtab_offset
			self.strtab_offset += len(name)+1
			
			#print "str_table: %s" % (str(self.str_table))
			print "self.strtab_dict:", self.strtab_dict
			
			print "current string table:"
			self.PrintStringTable()
		else:
			self.logger.debug("\tNot adding '%s' to string table (already present)" % name)
			
		return self.strtab_dict[name]
	
	def GetSectionIndexByName(self, function_name):
		''' Not sure what this as supposed to be used for
		
		'''
		print self.shdr_dict, self.shdr_table
		exit("implement this - pjdskf")
		
	def SectionNameToSectionHeaderIndex(self, section_name):
		''' Currently not implemented
		
		'''
		return 42
		#TODO: need a way to query for this. currently, self.sections_hex['.shstrtab'] is set in SetSHDependencies
		#		which is not called until WriteELF
		"""
		for name in self.sections_hex['.shstrtab'].split('\0'):
			pass
		#TODO: when this breaks, refactor BuildBaseSymbolTable and possibly the data structures it uses
		self.logger.warn("Could not find section entry for %s in symbol table" % section_name)
		return None
		"""
	
	def BuildBaseSymbolTable(self, function_name):
		''' Builds the base symbol table for an ELF object
			@param function_name: name of function
		'''
		
		logger.debug("Building base symbol table for function %s" % (function_name))
		
		# Create the default symbols for all object files
		# first entry must be the null entry as per ELF spec
		self.AddToSymbolTable('', 0, 0, STB_LOCAL, STT_NOTYPE, STO_DEFAULT, STN_UNDEF)
		
		# file name entry
		file_name = "%s.c" % function_name
		self.AddToSymbolTable(file_name, 0, 0, STB_LOCAL, STT_FILE, STO_DEFAULT, SHN_ABS)
		
		# Entries for each section (except .rel sections and shstrtab, symtab, strtb)
		current_section_index = 1 # index 0 is null section
		for section in self.sections_present:
			if ('.rel.' not in section) and (section not in ['.shstrtab', '.symtab', '.strtab']):
				logger.debug("Adding SECTION symbol for '%s'" % section)
				self.AddToSymbolTable('', 0, 0, STB_LOCAL, STT_SECTION, STO_DEFAULT, current_section_index)
				
			#else:
			#	self.symbol_table_index.append('')
			#TODO: this is a BUG!!! - should be incrementing to match the actual section index in the section headers
			current_section_index += 1
			
		
		# Last entry is for the function itself (function_name)
		if function_name == "main":
			symbol_name = "_delinked_" + function_name
		else:
			symbol_name = function_name
		st_value = 0
		st_size = self.shdr_dict['.text']['size']
		st_bind = STB_GLOBAL
		st_type = STT_FUNC
		st_other = STO_DEFAULT
		#TODO: implement GetSectionIndexByName
		#st_shndx = self.GetSectionIndexByName(function_name)
		st_shndx = 1 # this is a hack
		self.AddToSymbolTable(symbol_name, st_value, st_size, st_bind, st_type, st_other, st_shndx)


	def AddTextSymbol(self, symbol_name, symbol_type):
		#TODO: this function bypasses AddToSymbolTable and directly adds an entry to self.symbol_table
		#		a symbol table entry should probably only be added using one function
		''' Adds a symbol to the symbol table that is referenced somewhere in the text section
			(e.g., call f1, jmp f2, call printf@plt)
			
			@param name: name of symbol
			@param symbol_type: type of symbol (STT's in Constants.py)
			
			@return: location of the added symbol as an integer offset into the symbol table
		'''
		# these are undefined symbols that are defined in other object files (data.o or func.o)
		
		if symbol_name in self.symtab_dict:
			# already have an entry for this symbol
			logger.warn("NOT adding symbol table entry for '%s' -- symbol name already present" % symbol_name)
			
		else:
			logger.debug("Adding new text symbol: name: '%s'" % (symbol_name))
			
			value = 0
			size = 0
			st_bind = STB_GLOBAL # default to global for all symbols
			st_type = symbol_type
			seg_ndx = 0 # STT_UNDEF
			
			# name in .symtab is index into string table
			# we will use the self.strtab_offset that is saved within the object so that each new
			# entry into the string table starts after the last string 
			name_int = self.AddToStringTable(symbol_name)
			#seg_ndx = self.sections_present.index(seg_name) + 1
			symtab_entry = struct.pack("IIIBBH", name_int, value, size, self.GetSTInfo(st_bind, st_type), STO_DEFAULT, seg_ndx).encode('hex')
			
			# Add this entry to the symbol table
			self.symbol_table.append(symtab_entry)
			self.symbol_table_index.append(symbol_name)
			
			self.symtab_dict[symbol_name] = len(self.symbol_table) - 1 # the symbol table entry for symbol_name was the last entry added to symbol_table
		
		#TODO: only returns correct value if the 'else' condition above is executed
		#		this actually doesn't seem to be true...
		return self.symtab_dict[symbol_name]
	
	def AddToSymbolTable(self, symbol_name, st_value, st_size, st_bind, st_type, st_other, st_shndx):
		''' Processes a new symbol by crearing a symbol table entry with cooresponding string table entry
		
			@param symbol_name: name of the symbol : string
			@param st_value: depends on context (see below) : integer
			@param st_size: size in bytes of the symbol : integer
			@param st_bind: binding of the symbol : integer
			@param st_type: type of the symbol : integer
			@param st_other: unused value in ELF spec (should be STO_DEFAULT?) : integer
			@param st_shndx: 
			
			@return: location of this symbol as an integer offset into the symbol table
		'''
		'''
		typedef struct elf32_sym{
		  Elf32_Word	st_name;	# index into symbol string table; 0 == no name
		  Elf32_Addr	st_value;   # value of symbol - depends on context (Ex: absolute value, address, etc.)
		  Elf32_Word	st_size;	# size of symbol; 0 == no or unknown size
		  unsigned char st_info;	# specifies symbol's type and binding attributes
		  unsigned char st_other;   # always 0
		  Elf32_Half	st_shndx;   # index into section header table where symbol is defined; some indices indicate special meanings
		} Elf32_Sym;
		
		'''
		
		""" WTH is this for???
		data_object = False
		if func_start == 0:
			#assert head == 0
			data_object = True
			self.logger.debug("Adding %s to symbol table for DATA object" % (symbol_name)) 
			if seg_name == '.text':
				# pointers from data to text are undefined, global, NOTYPE, and have size=0
				size = 0
				type = STT_NOTYPE
				
				#TODO: think this is handled by seg_name == ''
				
			elif seg_name in ['.data','.rodata']:
				print "\tsymbol %s is defined in a data section" % symbol_name
				size = 4
				type = STT_OBJECT
			elif seg_name == '.bss':
				# value=0, size=0, type=NOTYPE, Bind=GLOBAL, Vis=DEFAULT, Ndx=UND, Name=symbol_name
				print "\tsymbol %s is defined in .bss section" % symbol_name
				
				size = 0
				type = STT_NOTYPE
				bind = STB_GLOBAL
			elif seg_name == '':
				# this is a function / jump table pointer
				print "\tsymbol %s is undefined (defined in .text)" % symbol_name
				size = 0
				type = STT_NOTYPE
			else:
				self.logger.error("Unsupported seg_name:'%s' in AddToSymbolTable" % seg_name)
				exit()
		elif func_start == 0xffffffff:
			# AddToSymbolTable was called with 
			data_object = True
			type = STT_OBJECT
		else:
			self.logger.debug("Adding to symbol table for FUNCTION object")
			exit("delinking a function... finish testing data object first")
			
		# validate seg_name and set Ndx
		seg_ndx = -1 # will cause error in readelf
		if seg_name == '':
			seg_ndx = 0 # undefined symbol
			
		elif seg_name in self.sections_present:
			print "\tsymbol is in %s section" % seg_name
			if seg_name == '.bss':
				seg_ndx = STN_UNDEF
			else:
				seg_ndx = self.sections_present.index(seg_name) + 1
		else:
			exit("illegal segment name '%s'" % seg_name)

		# validate size
		assert size >= 0
		# validate bind
		assert bind == STB_GLOBAL # only support global for now
		# validate type
		if size == 0:
			assert type == STT_NOTYPE
		
		if size != 0:
			assert (type == STT_FUNC or type == STT_OBJECT) and seg_ndx != 0
		
		#if value != 0:
		#	assert size != 0 # inverse not true
		
		"""		
		
		if symbol_name in self.symtab_dict and st_type != STT_SECTION:
			# already have an entry for this symbol (assumes unique names)
			self.logger.warn("NOT adding symbol table entry for '%s' -- symbol name already present" % symbol_name)
			#print self.symtab_dict
		else:
			#print "Found symbol: %s, %x %s, offset = %d " % (s, s, GetFunctionName(s), head - func_start)
			if st_type == STT_SECTION:
				self.logger.debug("Adding symbol entry for section [?]" )
			else:
				self.logger.debug("Adding new data symbol: name: '%s', value: %s, strtab offset: %d" % (symbol_name, st_value, self.strtab_offset))
			# name in .symtab is index into string table
			# we will use the self.strtab_offset that is saved within the object so that each new
			# entry into the string table starts after the last string 
			name = self.AddToStringTable(symbol_name)
			if st_shndx is None:
				st_shndx = STN_UNDEF
			
			symtab_entry = struct.pack("IIIBBH", name, st_value, st_size, self.GetSTInfo(st_bind, st_type), st_other, st_shndx).encode('hex')
			
			# Add this entry to the symbol table
			self.symbol_table.append(symtab_entry)
			self.symbol_table_index.append(symbol_name)
			
			
			self.symtab_dict[symbol_name] = len(self.symbol_table) - 1 # the symbol table entry for st_name was the last entry added to symbol_table
		
		return self.symtab_dict[symbol_name]
	
		
	def PatchBytes(self, patchee, patch, offset):
		''' Internal function to patch a hex string with a given patch at a given offset
			Attributes: patchee - hex string that needs patching
						patch - the patch to patch with
						offset - location in patchee to patch
			Returns: patched hex string
			patch
		'''
		patch_size = len(patch)
		assert offset + patch_size <= len(patchee)
		
		return patchee[0:offset] + patch + patchee[offset+patch_size:]
	
	def GetPadding(self, addr, al):
		''' Internal function to calculate proper offset based on current address and required alignment
			
			Attributes: addr - integer address needing alignment
						al - required integer alignment (use 2^x, not x)
						
			Returns: properly aligned integer address (address rounded up to next multiple of alignment)
		'''
		#assert al > 0
		assert al in [1,2,4,8,16,32,64,128,256,512,1024]
		adjustment = 0
		remainder = addr % al
		if remainder != 0: # if not already aligned
			adjustment = al - remainder
		return adjustment
	
	def ConcatNewSection(self, current_sections_hex, name):
		''' Given current sections, append alignment padding then append new section
			***Sets section offset in shdr_dict***
		
			Attributes: current_sections_hex - hex string of current output
						name - string name of the section to concatenate
			Returns: current_sections_hex with new_section_hex appended and properly aligned
		'''
		
		assert name in self.sections_hex
		
		new_section_hex = self.sections_hex[name]
		alignment = self.shdr_dict[name]['addralign']
		curr_len = len(current_sections_hex)/2 # length in bytes of the current hex string
		padding = self.GetPadding(curr_len, alignment)
		self.shdr_dict[name]['offset'] = curr_len + padding
		
		if self.shdr_dict[name]['type'] == 8: #NOBITS
			# len(self.sections_hex[name]) is 0 (since it is NOBITS)
			# and size was already set so nothin to do
			pass
		else:
			self.shdr_dict[name]['size'] = len(self.sections_hex[name]) / 2
		
		if name == '.bss': # bss holds no data but has a size -- this is handled in gcc by looking at section's Type field
			assert new_section_hex == ''
			self.logger.debug("Concat *NOBITS* section %s: \toffset 0x%x, size 0x%x" % (name, self.shdr_dict[name]['offset'], self.shdr_dict[name]['size']))

		elif new_section_hex == '' and self.shdr_dict[name]['size'] != 0:
			# section has undefined content but size > 0 : *assume* section will be patched in later, so fill with 0xff's
			new_section_hex = 'FF'*self.shdr_dict[name]['size']
			self.logger.debug("Concat *UNDEFINED* section %s: \toffset 0x%x, size 0x%x" % (name, self.shdr_dict[name]['offset'], self.shdr_dict[name]['size']))
		else:
			self.logger.debug("Concat section %s: \toffset 0x%x, size 0x%x" % (name, self.shdr_dict[name]['offset'], self.shdr_dict[name]['size']))
			
		print "new_section_hex: %s" % new_section_hex
		return current_sections_hex + "00"*padding + new_section_hex
	
	def BuildFuncObject(self, function_bytes, function_name, t2t_references):
		''' Builds an object file for function func_name
			
			@param function_bytes: raw bytes ot the text segment
			@param function_name: name of function
			@param t2t_references: list of tuples that define text-to-text references
							(e.g., call f1, jmp f2, call printf@plt)
							tuples are of the form: (offset into function where symbol is referenced,
													 symbol name that is being referenced
													)
		'''
		
		logger.debug("Building object for function %s" % (function_name))
		
		self.shdr_dict['.text']['size'] = len(function_bytes) # BuildBaseSymbolTable needs this set because it adds a symbol for the function
																# the function symbol creation should probably be done elsewhere
																# also note that the text size is also set in BuildText
		self.BuildBaseSymbolTable(function_name)
		
		# add all of the undefined symbols and relocation entries for each item in t2t_references
		for (offset, symbol_name) in t2t_references:
			print "\tprocessing refernce to symbol: %s" % symbol_name
			
			# make sure we are dealing with an external symbol
			# this should never happen... any? self-referencing operand would be encoded as PC-relative 
			assert symbol_name != function_name
			
			new_symbol_index = self.AddTextSymbol(symbol_name, STT_NOTYPE)
			
			# add the relocation entry
			self.AddRelocEntry(offset, R_386_PC32, '.text', symbol_name, new_symbol_index)
			
			# call to externally defined function (once we delink each function)
			# text = text[0:offset_into_function] + struct.pack("<I", -4) + text[offset_into_function+4:]
			function_bytes = function_bytes[0:offset] + '\xfc\xff\xff\xff' + function_bytes[offset+4:]
			print "\tpatched over address in 'call %s' at offset 0x%08x" % (symbol_name, offset)

		

		
		# !! self.reloc_text and self.ELFs[function_name].reloc_text are different 
		# below will not work - BuildText expects 
		self.BuildText(function_bytes)
	
		# Build final ELF
		self.BuildELF(function_name)
		
	
	def BuildText(self, code):
		''' Copies and 'unpatches' the function code
			TODO: size parameter not needed
		
			Attributes: code - hex string of function code
						size - integer size in bytes of the function
						XXXXtext_relocs - list of relocations that need to be applied
		'''
		logger.debug("Building .text section")
		
		size = len(code)
		logger.debug("\t.text size 0x%08x" % size)
		
		# below is deprecated -- now we are patching in Delinker_mod in for loop in BuildFuncObject
		#self.sections_hex['.text'] = self.PatchText(code, text_relocs) # right now just convert to hex
		code = code.encode('hex')
		self.sections_hex['.text'] = code
		self.shdr_dict['.text']['size'] = size # size in bytes
		

	def BuildELF(self, function_name):
		''' Responsible for creating the final ELF object file
			@param function_name: name of the function
		'''

		self.logger.debug("Building object for function %s" % function_name)
			
			
		# We are going to set all the remaining sizes in the section header table
		# so we can pass this data structure to the BuildSectionHeaders function
		
		#TODO: these do not belong here, move after relocs are handled properly
		self.logger.debug("setting shdr_dict['.symtab']['size'] -- %d symtab entries total" % len(self.symbol_table))
		self.shdr_dict['.symtab']['size'] = SYMTAB_ENTRY_SIZE * len(self.symbol_table)
		
		self.logger.debug("setting shdr_dict['.strtab']['size'] -- %d strtab entries total" % (len(self.str_table)+1))
		self.shdr_dict['.strtab']['size'] = (len("".join(self.str_table))/ 2) +1
		
		
		sh_tab_offset = 0
		offset = 0 
		current_size = ELFHDR_SIZE # cumulative size of sections as we examine them in the loop; first section should appear after elf header
		
		# Loop through each section header, calculate the offsets for each section and update the dictionary
		for section in ['.text','.data','.bss','.rodata','.shstrtab','.symtab','.strtab','.rel.text','.rel.data','.rel.rodata']:
			# NOTE: I think the alignment field is only used when creating the executable so don't use GetOffset for now
			# TODO: test this thought
			'''
			align = shdr_dict[shdr_name]['addralign']
			offset = self.GetOffset(current_size + offset, align)
			# update the offset of this section
			shdr_dict[shdr_name]['offset'] = offset
			current_size = shdr_dict[shdr_name]['size']
			'''
			
			# set the section offset and update cumulative size
			self.shdr_dict[section]['offset'] = current_size
			current_size += self.shdr_dict[section]['size']

		# build section headers in WriteELFObject
		self.WriteELFObject(function_name) # write the data/func object

	def WriteELFObject(self, function_name):
		''' Concatenates all of the sections according to proper alignment and sets the offsets
			Patches shoff, shnum, and shstrndx into the ELF header
		
			TODO: move actual file writing functionality to another function (or leave here and move everything else)
				  call ConcatNewSection in a loop in order of section_header_order
				  
			Attributes: function_name - name of function
		'''

		
		self.BuildElfHeader() # not passing sh_tab_offset -- compute and patch in WriteELFObject
		out = self.elfhdr
		"""
			Refactor this to by more dynamic
			
			Should iterate through each section and pseudosections (ELFheader, section headers) and set the corresponding section_hex
				some will be set already (move the setting to here for consistency?)
				others will not (e.g., rel.data, rel.rodata)
				if we do this in the same order that the sections will appear in the object file then we can keep an offset counter
					with this counter, we can set variables (sh_tab_offset, shnum, and shstrndx) so that we can patch them later
			Once all the sections are buffered to section_hex, write each section
		
		"""
		
		
		# add all the sections in order except add .shstrtab to the table last - then patch offset into elf header
		out = self.ConcatNewSection(out, '.text')
		out = self.ConcatNewSection(out, '.data')
		out = self.ConcatNewSection(out, '.bss')
		
		out = self.ConcatNewSection(out, '.rodata')
		
		out = self.ConcatNewSection(out, '.rel.text')
		
		
		out = self.ConcatNewSection(out, '.rel.data')
		
		
		out = self.ConcatNewSection(out, '.rel.rodata')
		
		
		
		# set up values needed for BuildSectionHeaders
		self.SetSHDependencies(self.shdr_dict) # Sets: sections_present; shdr_dict['.shstrtab']['size']; sections_hex[.shstrtab']
		
		out = self.ConcatNewSection(out, '.shstrtab')
		
		# compute and set sh_tab_offset
		out += '00'*self.GetPadding(len(out)/2, 4) # set up proper alignment before appending the section header table place holder
		sh_tab_offset = len(out)/2
		
		#TODO: this does not need to be here
		# patch sh_tab_offset, shnum, and shstrndx into elf header
		print "patching shoff 0x%x into ELF header" % sh_tab_offset
		out = self.PatchBytes(out, struct.pack("I", sh_tab_offset).encode('hex'), 64)
		print "patching shnum %d into ELF header" % (len(self.sections_present) + 1)
		out = self.PatchBytes(out, struct.pack('H', len(self.sections_present)+1).encode('hex'), 0x30*2)
		print "patching shstrndx %d into ELF header" % (self.sections_present.index('.shstrtab') + 1)
		############
		out = self.PatchBytes(out, struct.pack('H', self.sections_present.index('.shstrtab')+1).encode('hex'), 0x32*2)
		############
		
		# patch in the section header string table
		print "patching section header string table"
		out = self.PatchBytes(out, self.sections_hex['.shstrtab'], self.shdr_dict['.shstrtab']['offset']*2)
		
		# append section header table place holder (still don't have offset of the remaining sections - symtab and strtab)
		sh_offset = len(out)
		self.logger.debug("Concat manual 'section headers': \toffset 0x%x, size 0x%x" % (sh_offset, (len(self.sections_present)+1)*SHDR_ENTRY_SIZE))
		# already padded so just append the place holder
		out += 'FF'*(len(self.sections_present)+1)*SHDR_ENTRY_SIZE
		#TODO: ^ concat instead (must delegate as faux section first)
		
		# set contents of symtab and strtab
		self.sections_hex['.symtab'] = ''.join(self.symbol_table)
		self.sections_hex['.strtab'] = ''.join(self.str_table)
		
		out = self.ConcatNewSection(out, '.symtab')
		
		#print "self.sections_hex['.strtab']", self.sections_hex['.strtab']
		
		out = self.ConcatNewSection(out, '.strtab')
		#out = self.ConcatNewSection(out, '.rel.eh_frame')
		
		
		# all sections now have their offsets defined
		self.BuildSectionHeaders(self.shdr_dict) # should be called as late as possible
		# patch in the section headers starting at offset sh_offset, size len(''.join(self.shdr_table))/2
		print "patching in the section header table at offset 0x%x and size 0x%x" % (sh_offset, len(''.join(self.shdr_table)))
		out = self.PatchBytes(out, ''.join(self.shdr_table), sh_offset)
		
		
		tmp = binascii.unhexlify(out)
		tmp_bytes = [ord(x) for x in tmp]
		
		obj = bytearray(tmp_bytes)
		
		#TODO: use python path manip funcitons to construct path
		path = "delinked/%s" % (self.obj_filename)
		if not os.path.isdir(path):
			try:
				os.makedirs(path)
			except OSError:
				if not os.path.isdir(path):
					logger.error("Could not create directory %s" % path)
				else:
					logger.error("unbhandled exception in WriteELFObject")
				return

		obj_file = "%s/%s.o" % (path, function_name)

		with open (obj_file, "wb") as f:
			logger.info("Wrote %s" % obj_file)
			f.write(obj)
		
		print '\n'*4
		self._Sanity()
		
	def _Sanity(self):
		''' Spot elusive bugs '''
		assert len(self.sections_hex) == 10 # find key typos when overwriting key's value
	
'''

Headers for Reference:

typedef struct elf32_sym{
  Elf32_Word	st_name;
  Elf32_Addr	st_value;
  Elf32_Word	st_size;
  unsigned char st_info;
  unsigned char st_other;
  Elf32_Half	st_shndx;
} Elf32_Sym;


typedef struct elf32_rel {
  Elf32_Addr	r_offset;   # For a relocatable file, the value is the byte offset from the beginning of the section to the storage unit affected by the relocation.
  Elf32_Word	r_info;	 # 
} Elf32_Rel;

typedef struct elf32_rela{
  Elf32_Addr	r_offset;
  Elf32_Word	r_info;
  Elf32_Sword   r_addend;
} Elf32_Rela;

#define EI_NIDENT   16

'''