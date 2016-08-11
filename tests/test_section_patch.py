# Test patching a section

import sys
import subprocess
sys.path.append("../elfmanip")

from ELFManip import ELFManip, Custom_Section, Custom_Segment
from Constants import PT_LOAD, PF_R

TEST_FILE = "test_section_patch"
OUT_FILE = TEST_FILE + '.patched'
REPLACE_THIS = "bonjour le monde!\x00"
WITH_THIS = "hello world!\x00"

def main():
    elf = ELFManip(TEST_FILE, num_adtl_segments=0)
    
    found = False
    for section in elf.shdrs['entries']:
        section_bytes = section.get_original_bytes()
        if REPLACE_THIS in section_bytes:
            found = True
            section.write(WITH_THIS, section_bytes.index(REPLACE_THIS))
    
    assert found
    
    elf.write_new_elf(OUT_FILE)
    
    assert subprocess.check_output(["./" + OUT_FILE]) == WITH_THIS[:-1] + "\n"
            

if __name__ == "__main__":
    main()