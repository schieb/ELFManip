
fname = '../tests/erick/segment-issue/sort'
nname = '../tests/erick/segment-issue/sort-r'
newcode = '../tests/erick/segment-issue/newbytes'
newbase = 0x9000000
newglobal = '../tests/erick/segment-issue/newglobal'
newglobalbase = 0x7000000
entry = 0x90025ad


from elfmanip import ELFManip, CustomSection, CustomSegment
from constants import PT_LOAD

def rewrite(fname, nname, newcode, newbase, newglobal, newglobalbase, entry):
    elf = ELFManip(fname, num_adtl_segments=2)

    old_phdr_base = elf.phdrs['base']
    elf.relocate_phdrs()
    new_phdr_base = elf.phdrs['base']

    with open(newcode) as f:
        newbytes = f.read()

    newtext_section = CustomSection(contents=newbytes, sh_addr=newbase)
    newglobal_section = CustomSection(newglobal, sh_addr=newglobalbase)
    if newtext_section is None or newglobal_section is None:
        raise Exception


    newtext_segment = CustomSegment(PT_LOAD)
    newtext_segment = elf.add_segment(newtext_segment)

    newglobal_segment = CustomSegment(PT_LOAD)
    newglobal_segment = elf.add_segment(newglobal_segment)

    elf.add_section(newtext_section, newtext_segment)
    elf.add_section(newglobal_section, newglobal_segment)

    elf.set_entry_point(entry)
    elf.write_new_elf(nname)


if __name__ == "__main__":
    rewrite(fname, nname, newcode, newbase, newglobal, newglobalbase, entry)
