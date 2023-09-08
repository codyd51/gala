#!/bin/sh

#  compile_payload2.sh
#  jailbreak
#
#  Created by Phillip Tennen on 10/07/2023.
#  
as -arch armv7 entry.s -o build/entry.o
ld build/entry.o -U _main -U start -static -o build/kernelcache_set_debug_enabled_packed
python3 ../dump_shellcode.py build/kernelcache_set_debug_enabled_packed build/kernelcache_set_debug_enabled_shellcode
