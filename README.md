# Elf virus

A virus which infects elf 64 bits executables.

It uses the PT_NOTE to PT_LOAD method to inject itself into targets.
The virus injects itself partly obfuscated and unobfuscate its code at runtime.
It carries a signature that will never be the same for each infection.
It won't execute itself if gdb is running or if the program is being debugged.
The code is metamorphic, it will never be the same for any infection even on the same binaries.
