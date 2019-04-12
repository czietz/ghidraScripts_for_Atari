# This script imports an Atari TOS program into Ghidra creating TEXT, DATA, BSS sections
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
import jarray

# Arbitrary address to relocate program to
reloc_addr = 0x10000

# Ask user for the file to import
file = askFile("Please specify a file to import", "Import")

# Import as binary file for 68k CPU since there is no builtin support for TOS program file format
lang = getDefaultLanguage(ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("68000"))
comp = lang.getDefaultCompilerSpec()
program = importFileAsBinary(file, lang, comp)
flat = ghidra.program.flatapi.FlatProgramAPI(program)

# Initialize some variables
txn = program.startTransaction("Import program")
mem = program.getMemory()
start = mem.getMinAddress()

# Check for "magic" number in header
magic = mem.getShort(start)
if magic != 0x601a:
	raise Exception("Not a TOS program!")

# Data from PRG header
len_text = mem.getInt(start.add(0x2))
len_data = mem.getInt(start.add(0x6))
len_bss  = mem.getInt(start.add(0xa))
len_sym  = mem.getInt(start.add(0xe))

# Keep symbol table for later use
if len_sym > 0:
    sym_table = jarray.zeros(len_sym, "b")
    mem.getBytes(start.add(0x1c+len_text+len_data), sym_table)
    sym_table = bytearray(sym_table) # to native Python type

# Relocate program
prg = start.add(0x1c)
ptr = start.add(0x1c+len_text+len_data+len_sym) # start of relocation table
rea = mem.getInt(ptr) # first address to relocate
ptr = ptr.add(4)
if rea != 0:
	# print("Relocating %x (%08x => %08x)" % (rea, mem.getInt(prg.add(rea)), mem.getInt(prg.add(rea))+reloc_addr))
	mem.setInt(prg.add(rea), mem.getInt(prg.add(rea)) + reloc_addr)
	while True:
		offs = mem.getByte(ptr)
		if offs<0: # byte is *signed* in Java/Jython
			offs=256+offs
		ptr = ptr.add(1)
		if offs == 0: # end of table
			break
		if offs == 1: # advance by 254
			rea = rea + 254
			continue
		rea = rea + offs
		# print("Relocating %x (%08x => %08x)" % (rea, mem.getInt(prg.add(rea)), mem.getInt(prg.add(rea))+reloc_addr))
		mem.setInt(prg.add(rea), mem.getInt(prg.add(rea)) + reloc_addr)


# Header Block, split off actual TEXT, DATA sections
bl_hdr = mem.getBlocks()[0] # only one block exists right now
bl_hdr.setName("Program Header")
mem.split(bl_hdr, start.add(0x1c))

# Create TEXT and DATA sections at relocated address
bl_text = mem.getBlocks()[-1] # newly split block
bl_text.setName("TEXT")
text_start = start.add(reloc_addr)
data_start = text_start.add(len_text)
bss_start =  data_start.add(len_data)
mem.moveBlock(bl_text, text_start, ghidra.util.task.TaskMonitor.DUMMY)

# Split off data block
mem.split(bl_text, data_start)
bl_data = mem.getBlocks()[-1] # newly split block
bl_data.setName("DATA")

# Delete everything after end of DATA, create new empty BSS block instead
mem.split(bl_data, bss_start)
bl_bss = mem.getBlocks()[-1] # new block
mem.removeBlock(bl_bss, ghidra.util.task.TaskMonitor.DUMMY)
bl_bss = mem.createUninitializedBlock("BSS", bss_start, len_bss, False)
bl_bss.setRead(True)
bl_bss.setWrite(True)

# Change the name of the fragment created when program was loaded
frag = program.getTreeManager().getFragment(ghidra.program.database.module.TreeManager.DEFAULT_TREE_NAME, start)
frag.setName("Header, TEXT, DATA")

# Import symbol table if the user wants to
# Primitive plausibility check: a DRI/GST symbol table size always is a multiple of 14
if len_sym > 0 and (len_sym % struct.calcsize(">8sHL")) == 0 and askYesNo("Import", "Import symbol table?") == True:
    s_ptr = 0
    while s_ptr < len_sym:
        s_name, s_id, s_addr = struct.unpack_from(">8sHL", bytes(sym_table), s_ptr)
        s_ptr += struct.calcsize(">8sHL")

        # extended GST format: read name from next slot
        if s_id & 0x48 != 0:
            s_name = s_name + struct.unpack_from(">14s",  bytes(sym_table), s_ptr)[0]
            s_ptr += struct.calcsize(">14s")

        s_name = s_name.rstrip("\0")

        # skip symbols containing file names
        if s_name[-2:] == ".o" or s_name[-2:] == ".a" or s_name[0] == "/":
            continue

        s_type = s_id & 0xf00
        if s_type == 0x200: # TEXT
            flat.createLabel(text_start.add(s_addr), s_name, False)
        elif s_type == 0x400: # DATA
            flat.createLabel(data_start.add(s_addr), s_name, False)
        elif s_type == 0x100: # BSS
            flat.createLabel(bss_start.add(s_addr),  s_name, False)
        else: # unsupported type
            pass

# Add some labels
flat.createDwords(start.add(0x2), 4)
flat.createLabel(start.add(0x2), "TEXT_LEN", True)
flat.createLabel(start.add(0x6), "DATA_LEN", True)
flat.createLabel(start.add(0xa), "BSS_LEN", True)
flat.createLabel(start.add(0xe), "SYM_LEN", True)
flat.createLabel(text_start, "ENTRY_POINT", True)

# Run disassembler on entry point
flat.disassemble(text_start)

# Open for user to see and to start analyzing
program.endTransaction(txn, True)
openProgram(program)

