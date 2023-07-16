
Need to assemble some shellcode
Assemble it with as, but that includes a MachO wrapper -- just want the raw inner bytes
Pull them out with strongarm, but strongarm crashes due to missing load command when trying to read the symtab
OK make a full binary, but ld doesn't like missing symbols

as -arch armv7 assemble2.s -o dumper_macho.o

 ld dumper_macho.o
Undefined symbols for architecture armv7:
  "_main", referenced from:
     implicit entry/start for main executable
ld: symbol(s) not found for architecture armv7

 ld dumper_macho.o -U _main
ld: dynamic executables or dylibs must link with libSystem.dylib for architecture armv7

 ld dumper_macho.o -U _main -framework libSystem.dylib -o test.o
ld: framework not found libSystem.dylib

man page mentions "static"
 ld dumper_macho.o -U _main -o test.o -static
Undefined symbols for architecture armv7:
  "start", referenced from:
     -u command line option
ld: symbol(s) not found for architecture armv7

ld dumper_macho.o -U _main -U start -static -o test.o

still missing a load command when trying to read the bound symbols (i guses it's linkedit missing, since it's -static')
just comment out the line in strongarm


https://archive.conference.hitb.org/hitbsecconf2013kul/materials/D2T1%20-%20Joshua%20'p0sixninja'%20Hill%20-%20SHAttered%20Dreams.pdf
" LimeRa1n appears to be a race condition heap buffer overflow in USB stack.
•  After release I asked @geohot to explain why it worked.
•  He said he had no clue, but I will speculate on my theory in the next part.""

https://ipsw.me/download/iPhone3,1/10B329

difficult to write anything that plays around in userspace because there's no way to set up a toolchain for iOS 4 / iOS 6 -- so bootROM exploits are the only good choice


can't use "const char* x = "..." in C becuase it'll be put in __cstring, which is lost when we creaet the shellcode
any strings need to be `.asciz` in assembly and loaded that way

can't really load the address using extern in C, because it's relative to PC
solution: pass the address from asm to the C function
fiddled a lot with ldr =symbol, etc, finally got `adr symbol` and it workrs


load_selected_image returning -1! but it's directly from the IPSW?

We acutally need two kinds of patches: the structured "replace these instructions with these other instructions" that we've been using for hand-written patches,
and a "replace this blob with another blob", which is useful for injecting a tiny test program. The latter is useful when injecting shellcode to do a bit of extra logging when debugging something going wrong

Kept running off into opcode zero, needed to do pop {pc}

When I first wrote "INJECTED LOG" it'd overwrite critical instructions next door!