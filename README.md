# ghidraScripts_for_Atari
Scripts to simplify analysis of Atari TOS code with Ghidra (software reverse engineering framework).

Ghidra is a powerful cross-platform software reverse engineering framework, which also supports the Motorola 68k architecture used in Atari ST/TT/Falcon computers. The scripts in this repository are meant to help with the analysis of Atari software.

## Starting with Ghidra
Download it from https://ghidra-sre.org/. This site also has a _Getting Started_ video, an installation guide and a quick reference to show you the first steps with Ghidra. [Ghidra: A quick overview for the curious](http://0xeb.net/2019/03/ghidra-a-quick-overview/) has a nice illustrated tour through some of the features.

## Installing and running the scripts
Copy the scripts into a script directory. By default, Ghidra looks into `$USER_HOME/ghidra_scripts`, i.e., `ghidra_scripts` in your home directory. (`%USERPROFILE%` for Windows.)
To run a script, open a _Code Browser_ window. (Click the button with the dragon in the Ghidra project manager.) Open the _Script Manager_ (Window -> Script Manager). Right-click on the script and select _Run_.

## Short description of scripts
* __ImportAtariPRG.py__: Imports a TOS program (PRG, TOS, TTP, APP, ...) into Ghidra. It creates a memory map for TEXT, DATA and BSS sections from the program header.
* __ImportAtariTOS.py__: Imports a TOS ROM image into Ghidra. It automatically determines the correct address range from the header. Optionally, when importing an EmuTOS image, you can load a symbol file created by the `map2sym.sh` script provided with EmuTOS. In that case public symbols will be named correctly in Ghidra. (Click _Cancel_ if you don't want to load a symbol file.)

## Ideas for future development
* A script to annotate TRAPs (OS calls) according to function number.
* A script to handle Line A (low level graphic) calls.
* Importing symbol table in programs, if present.
