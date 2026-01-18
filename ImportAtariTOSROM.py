# This script imports an Atari TOS ROM into Ghidra. Optionally it can also import an EmuTOS symbol file created by map2sym.sh.
#@author Christian Zietz
#@category Import
#@runtime Jython
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

# Ask user for the file to import
file = askFile("Please specify a file to import", "Import")

# Import as binary file for 68k CPU since there is no builtin support for TOS program file format
lang = getDefaultLanguage(ghidra.program.model.lang.Processor.findOrPossiblyCreateProcessor("68000"))
comp = lang.getDefaultCompilerSpec()
program = importFileAsBinary(file, lang, comp)

# Initialize some variables
txn = program.startTransaction("Import program")
mem = program.getMemory()
zero = mem.getMinAddress()

# Check for "magic" number in header
magic = mem.getByte(zero)
if magic != 0x60:
	raise Exception("Not a TOS ROM!")

# Data from TOS header
tosstart = zero.add(mem.getInt(zero.add(0x4)))
tosbase = zero.add(mem.getInt(zero.add(0x8)))

# Move to correct address
mem.moveBlock(mem.getBlocks()[0], tosbase, ghidra.util.task.TaskMonitor.DUMMY)

# Create new empty BSS block
bss = mem.createUninitializedBlock("BSS", zero, 0x10000, False)
bss.setRead(True)
bss.setWrite(True)

# Change the name of the fragment created when program was loaded
frag = program.getTreeManager().getFragment(ghidra.program.database.module.TreeManager.DEFAULT_TREE_NAME, tosbase)
frag.setName("ROM")

# Add some labels and start disassembly
flat = ghidra.program.flatapi.FlatProgramAPI(program)
flat.createLabel(tosstart, "RESET_HANDLER", True)
flat.disassemble(tosstart)

# Read EmuTOS symbol file
try:
	file = askFile("Optionally select symbol file (or click cancel)", "Open")
	file = open(file.toString(), "r")
	for line in file:
		line = line.strip()
		addr, type, name = line.split(" ")
		flat.createLabel(flat.toAddr(addr), name, False)
except ghidra.util.exception.CancelledException:
	# user clicked Cancel
	pass
except:
	raise

# Open for user to see and to start analyzing
program.endTransaction(txn, True)
openProgram(program)
