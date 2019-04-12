# This script imports an a.out object file as created my m68k-atari-mint-gcc into Ghidra
#@author Christian Zietz
#@category Import
#@keybinding 
#@menupath 
#@toolbar 

# Copyright (c) 2019 Christian Zietz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import struct
import os.path

# check if running under Ghidra, so that for debug purposes we can run without it
in_ghidra = "currentProgram" in globals()

# arbitrary addresses for sections
text_addr = 0x100000
data_addr = 0x200000
bss_addr  = 0x300000
ext_addr  = 0x400000

# because Ghidra's Python doesn't have this
def my_iter_unpack(fmt, buffer):
    fmtsize = struct.calcsize(fmt)
    for i in range(0, len(buffer), fmtsize):
        yield struct.unpack_from(fmt, buffer, i)

# get a zero terminated string from a buffer, starting at pos
def get_string(s, pos):
   term = s.find(b"\0", pos + 1)
   if term != -1:
      return s[pos:term].decode("ascii")
   else:
      return s[pos:].decode("ascii")

# add an initialized section to Ghidra
def ghidra_add_section_from_array(name, address, data):
    address = parseAddress("0x%x" % address)
    createMemoryBlock(name, address, bytes(data), False)

# add an uninitialized section to Ghidra
def ghidra_add_section_uninit(name, address, len):
    address = parseAddress("0x%x" % address)
    createMemoryBlock(name, address, None, len, False)

# process a relocation table and relocate a section
def relocate_section(table, section, name):
    for (r_addr, r_info) in my_iter_unpack(">LL", table):
        if r_info & 0x8f != 0:
            print("Unknown relocation type %d" % r_info & 0xff)
        else:
            r_num = r_info >> 8
            if r_info & 0x10 != 0:
                # external relocation look up symbol
                r_fix = symbols[r_num]["addr"]
                #print("Relocating %s at %s:%x" % (symbols[r_num]["name"], name, r_addr))
            else:
                # reference to segment, however the data at r_addr is always relative to start of TEXT! 
                if r_num == 4: # TEXT
                    r_fix = text_addr
                elif r_num == 6: # DATA
                    r_fix = data_addr - text_size
                elif r_num == 8: # BSS
                    r_fix = bss_addr - text_size - data_size
                else: # error?
                    r_fix = None
            # length
            r_len = (r_info & 0x7f) >> 5
            if r_len == 1:
                # short
                section[r_addr:r_addr+2] = struct.pack(">H", r_fix + struct.unpack_from(">h", bytes(section[r_addr:r_addr+2]))[0])
            elif r_len == 2:
                # long
                section[r_addr:r_addr+4] = struct.pack(">L", r_fix + struct.unpack_from(">l", bytes(section[r_addr:r_addr+4]))[0])
            else:
                print("Unknown relocation size %d" % r_len)

# open file
if in_ghidra:
    file = askFile("Select A.OUT object (*.o) to import", "Import")
    aout = open(file.toString(), "rb")
else:
    aout = open(r"C:\temp\testaout.o", "rb")

# read header
header_size = 0x20
magic, text_size, data_size, bss_size, sym_size, entry, tr_size, dr_size = struct.unpack(">8L", aout.read(header_size))
ext_size = 0 # fictious section for external references

# read symbol table
aout.seek(header_size + text_size + data_size + tr_size + dr_size)
symbol_table = aout.read(sym_size)

# read and parse string table
string_size, = struct.unpack(">L", aout.read(4))
string_table = aout.read(string_size)
# strings = string_table.decode("ascii").split("\0")

# parse symbol table into list
symbols = []
for (n_strx, n_type, n_other, n_desc, n_value) in my_iter_unpack(">lBbhL", symbol_table):
    n_strx -= 4 # because we read the first four byte separately
    n_name = get_string(string_table, n_strx)
    n_type &= 0x1e # mask for type
    if n_type == 0x00: # undefined or common
        if n_value == 0: # undefined=external symbol
            # create external symbol arbitrarily sized 4 bytes
            n_addr = ext_addr + ext_size
            ext_size += 4
        else: # common symbol = uninitialized variable with given length
            # add to bss
            n_addr = bss_addr + bss_size
            bss_size += n_value
    elif n_type == 0x02: # absolute
        n_addr = n_value
    elif n_type == 0x04: # text
        n_addr = n_value + text_addr
    elif n_type == 0x06: # data
        n_addr = n_value + data_addr - text_size
    elif n_type == 0x08: # bss
        n_addr = n_value + bss_addr - text_size - data_size
    else:
        print("Unknown symbol type %d" % n_type)
        n_addr = None
    symbols += [{"name":n_name,"addr":n_addr}]

# read text and data sections and relocation tables
aout.seek(header_size)
text_section = bytearray(aout.read(text_size)) # bytearray is mutable
data_section = bytearray(aout.read(data_size))
tr_table = aout.read(tr_size)
dr_table = aout.read(dr_size)
aout.close()

# relocate text and data section
relocate_section(tr_table, text_section, "TEXT")
relocate_section(dr_table, data_section, "DATA")

# create a new 68K ghidra program
if in_ghidra:
    lang = getDefaultLanguage(ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("68000"))
    comp = lang.getDefaultCompilerSpec()
    program = createProgram(os.path.basename(file.toString()), lang, comp)
    txn = program.startTransaction("Import object file")
    # add sections
    if text_size > 0:
        ghidra_add_section_from_array(".text", text_addr, text_section)
    if data_size > 0:
        ghidra_add_section_from_array(".data", data_addr, data_section)
    if bss_size > 0:
        ghidra_add_section_uninit(".bss", bss_addr, bss_size)
    if ext_size > 0:
        ghidra_add_section_uninit(".import", ext_addr, ext_size)
    # add symbols
    for sym in symbols:
        if sym["name"][0:2] != ".L":
            # skip local labels
            createLabel(parseAddress("0x%x" % sym["addr"]), sym["name"], False)

    program.endTransaction(txn, True)
    openProgram(program)
