# This script imports an Idris program file
#@author Christian Zietz
#@category Import
#@runtime Jython
#@keybinding 
#@menupath 
#@toolbar 

# Copyright (c) 2025 Christian Zietz
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

# add an initialized section to Ghidra
def ghidra_add_section_from_array(name, address, data, r, w, x):
    address = parseAddress("0x%x" % address)
    mb = createMemoryBlock(name, address, bytes(data), False)
    mb.setPermissions(r, w, x)

# add an uninitialized section to Ghidra
def ghidra_add_section_uninit(name, address, len, r, w, x):
    address = parseAddress("0x%x" % address)
    mb = createMemoryBlock(name, address, None, len, False)
    mb.setPermissions(r, w, x)

# open file
if in_ghidra:
    file = askFile("Select Idris binary to import", "Import")
    aout = open(file.toString(), "rb")
else:
    aout = open(r"C:\temp\idris\less", "rb")

# read header
header_size = 0x1C
magic, sym_size, text_size, data_size, bss_size, stack_size, text_addr, data_addr = struct.unpack(">HH6L", aout.read(header_size))

# TODO: check if this is always correct
bss_addr = data_addr + data_size

if (magic & 0xfff8) != 0x9928:
    raise Exception("Unexpected magic number! Not an Idris ST binary?")

# read symbol table
aout.seek(header_size + text_size + data_size)
symbol_table = aout.read(sym_size)

# read text and data sections
aout.seek(header_size)
text_section = bytearray(aout.read(text_size)) # bytearray is mutable
data_section = bytearray(aout.read(data_size))

# parse symbol table into list
symbols = []
idx = 0
if magic == 0x9928:
    while idx < sym_size:
        n_addr, n_type, n_strlen = struct.unpack_from(">LBB", symbol_table, idx)
        idx = idx + 6
        n_name = symbol_table[idx:idx+n_strlen]
        idx = idx + n_strlen
        symbols += [{"name":n_name,"addr":n_addr,"type":n_type}]
else:
    symbol_length = ((magic & 7) * 2) + 1
    while idx < sym_size:
        n_addr, n_type = struct.unpack_from(">LB", symbol_table, idx)
        idx = idx + 5
        n_name = symbol_table[idx:idx+symbol_length].rstrip("\0")
        idx = idx + symbol_length
        symbols += [{"name":n_name,"addr":n_addr,"type":n_type}]

# create a new 68K ghidra program
if in_ghidra:
    lang = getDefaultLanguage(ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("68000"))
    comp = lang.getDefaultCompilerSpec()
    program = createProgram(os.path.basename(file.toString()), lang, comp)
    txn = program.startTransaction("Import object file")
    # add sections
    if text_size > 0:
        ghidra_add_section_from_array(".text", text_addr, text_section, True, False, True)
    if data_size > 0:
        ghidra_add_section_from_array(".data", data_addr, data_section, True, True, False)
    if bss_size > 0:
        ghidra_add_section_uninit(".bss", bss_addr, bss_size, True, True, False)
    # add symbols
    for sym in symbols:
        if sym["name"][0] != "\t":
            createLabel(parseAddress("0x%x" % sym["addr"]), sym["name"], False)

    program.endTransaction(txn, True)
    openProgram(program)
