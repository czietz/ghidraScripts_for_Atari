# ghidraScripts_for_Atari
Scripts to simplify analysis of Atari TOS code with Ghidra (software reverse engineering framework).

Ghidra is a powerful cross-platform software reverse engineering framework, which also supports the Motorola 68k architecture used in Atari ST/TT/Falcon computers. The scripts in this repository are meant to help with the analysis of Atari software.

## Starting with Ghidra
Download it from https://ghidra-sre.org/. This site also has a _Getting Started_ video, an installation guide and a quick reference to show you the first steps with Ghidra. [Ghidra: A quick overview for the curious](http://0xeb.net/2019/03/ghidra-a-quick-overview/) has a nice illustrated tour through some of the features.

## Installing and running the scripts
Copy the scripts into a script directory. By default, Ghidra looks into `$USER_HOME/ghidra_scripts`, i.e., `ghidra_scripts` in your home directory. (`%USERPROFILE%` for Windows.)
To run a script, open a _Code Browser_ window. (Click the button with the dragon in the Ghidra project manager.) Open the _Script Manager_ (Window -> Script Manager). Right-click on the script and select _Run_.

## Short description of scripts and files
* __ImportAtariPRG.py__: Imports a TOS program (PRG, TOS, TTP, APP, ...) into Ghidra. It creates a memory map for TEXT, DATA and BSS sections from the program header. It can also optionally import a symbol table in DRI/GST format, the creation of which is supported by many compilers. (For m68k-atari-mint-gcc use the `-Wl,--traditional` option to create a suitable symbol table.)
* __ImportAtariTOS.py__: Imports a TOS ROM image into Ghidra. It automatically determines the correct address range from the header. Optionally, when importing an EmuTOS image, you can load a symbol file created by the `map2sym.sh` script provided with EmuTOS. In that case public symbols will be named correctly in Ghidra. (Click _Cancel_ if you don't want to load a symbol file.)
* __ImportAOutObject.py__: Imports an object (.o) file in the a.out file format, as created by m68k-atari-mint-gcc/m68k-atari-mint-gas. It creates sections for TEXT, DATA, BSS and external symbols and imports the symbols from the symbol table.
* __mintlib.fidbf__: A nice feature of Ghidra is _Function ID_. Quoting the [documentation](https://ghidra.online/Ghidra/Features/FunctionID/lib/FunctionID.jar/help/topics/FunctionID/FunctionID.html): »Function ID is an analyzer that performs function identification analysis on a program. [...] Function ID is suitable for identifying statically linked libraries [...]. Because of the hashing strategy, functions remain identifiable even if the library is relocated during linking.« This file is a database for MiNTLib as provided by [Vincent Rivière's m68k-atari-mint cross-tools](http://vincent.riviere.free.fr/soft/m68k-atari-mint/). Currently it only contains the standard C library for the 68000 target. `mintlib.fidbf` needs to be copied to `Ghidra/Features/FunctionID/data`. When loading a program built using this MiNTLib version, Ghidra can be told via Analysis -> One Shot -> Function ID to identify any standard library functions, greatly simplifying analysis of unknown programs.
* __system_variables.txt__: A list of system variables from [tos.hyp](https://freemint.github.io/tos.hyp/en/bios_sysvars.html). To import, use ImportSymbolsScript.py that comes with Ghidra.

## Ideas for future development
* A script to annotate TRAPs (OS calls) according to function number.
* A script to handle Line A (low level graphic) calls.
* Adding hardware addresses to system_variables.txt.

