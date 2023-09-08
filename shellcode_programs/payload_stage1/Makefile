#  Makefile
#  jailbreak
#
#  Created by Phillip Tennen on 08/07/2023.
#

build/payload_stage1_packed build/payload_stage1_shellcode:
	as -arch armv7 entry.s -o build/entry.o
	#as -arch armv7 entry_for_demo.s -o build/entry.o
	gcc -c -arch armv7 launch_image.c -ffreestanding -o build/launch_image.o -mthumb -fpic
	#ld build/entry.o build/launch_image.o -U _main -U start -static -o build/payload_stage1_packed
	ld build/entry.o /Users/philliptennen/Documents/Jailbreak/gala/securerom_payload/target/armv7-apple-ios/debug/libsecurerom_payload.a -U _main -U start -static -o build/payload_stage1_packed
	#ld build/entry.o build/launch_image.o
	#ld build/entry.o ../securerom_payload/stripped_rust_payload -U _main -U start -static -o build/payload_stage1_packed
	python3 ../dump_shellcode.py build/payload_stage1_packed build/payload_stage1_shellcode
