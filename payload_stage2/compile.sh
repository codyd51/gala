#!/bin/sh

#  compile_payload2.sh
#  jailbreak
#
#  Created by Phillip Tennen on 10/07/2023.
#  
as -arch armv7 entry.s -o build/entry.o
gcc -c -arch armv7 body.c -ffreestanding -o build/body.o -mthumb -fpic
ld build/entry.o build/body.o -U _main -U start -static -o build/payload_stage2_packed
python3 ../dump_shellcode.py build/payload_stage2_packed build/payload_stage2_shellcode
~/Documents/Jailbreak/xpwn/build/ipsw-patch/xpwntool build/payload_stage2_shellcode build/payload_stage2_shellcode.img3 -t ~/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu -k 5986012d3cd4174b82d1ed5cdc2d0bc0a2bf1ac2f1afeab2ec7b04446be08ce6 -iv b65e495bc0f82471575301f38c9216d8


as -arch armv7 entry_test.s -o build/entry_test.o
# ld payload2_tiny_asm.o payload2_c.o -U _main -U start -static -o payload2
ld build/entry_test.o -U _main -U start -static -o build/payload_stage2_packed
python3 ../dump_shellcode.py build/payload_stage2_packed build/payload_stage2_shellcode
~/Documents/Jailbreak/xpwn/build/ipsw-patch/xpwntool build/payload_stage2_shellcode build/payload_stage2_shellcode.img3 -t ~/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/Firmware/dfu/iBSS.n90ap.RELEASE.dfu -k 5986012d3cd4174b82d1ed5cdc2d0bc0a2bf1ac2f1afeab2ec7b04446be08ce6 -iv b65e495bc0f82471575301f38c9216d8
