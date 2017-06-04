# This example shows very basic functionality of replacing one sequence of bytes with another

from elfmanip import ELFManip

TEST_FILE = "patch_me"
OUT_FILE = TEST_FILE + '.patched'
REPLACE_THIS = "bonjour le monde!\x00"
WITH_THIS = "hello world!\x00"

def main():
    elf = ELFManip(TEST_FILE, num_adtl_segments=0)

    for section in elf.shdrs['entries']:
        section_bytes = section.get_original_bytes()
        if REPLACE_THIS in section_bytes:
            section.write(WITH_THIS, section_bytes.index(REPLACE_THIS))

    elf.write_new_elf(OUT_FILE)

if __name__ == "__main__":
    main()
