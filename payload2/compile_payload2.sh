#!/bin/sh

#  compile_payload2.sh
#  jailbreak
#
#  Created by Phillip Tennen on 10/07/2023.
#  
as -arch armv7 payload2.s -o payload2_asm.o
gcc -c -arch armv7 payload2.c -ffreestanding -o payload2_c.o -mthumb -fpic
ld payload2_asm.o payload2_c.o -U _main -U start -static -o payload2
python3 ../dump_shellcode.py ./payload2 ./trimmed_shellcode2
~/Documents/Jailbreak/xpwn/build/ipsw-patch/xpwntool ./trimmed_shellcode2 ./trimmed_shellcode.img3 -t ~/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu -k 5986012d3cd4174b82d1ed5cdc2d0bc0a2bf1ac2f1afeab2ec7b04446be08ce6 -iv b65e495bc0f82471575301f38c9216d8


as -arch armv7 payload2_tiny.s -o payload2_tiny_asm.o
# ld payload2_tiny_asm.o payload2_c.o -U _main -U start -static -o payload2
ld payload2_tiny_asm.o -U _main -U start -static -o payload2
python3 ../dump_shellcode.py ./payload2 ./trimmed_shellcode2
~/Documents/Jailbreak/xpwn/build/ipsw-patch/xpwntool ./trimmed_shellcode2 ./trimmed_shellcode.img3 -t ~/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu -k 5986012d3cd4174b82d1ed5cdc2d0bc0a2bf1ac2f1afeab2ec7b04446be08ce6 -iv b65e495bc0f82471575301f38c9216d8
