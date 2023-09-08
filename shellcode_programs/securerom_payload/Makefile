#  Makefile
#  gala
#
#  Created by Phillip Tennen on 08/07/2023.
#

build/securerom_payload_packed build/securerom_payload_shellcode:
	as -arch armv7 entry.s -o build/entry.o
	# PT: Note we need to use the nightly-2020-01-01-x86_64-apple-darwin toolchain, as
	# the armv7-apple-ios target was dropped in newer Rust releases.
	# Ref: https://blog.rust-lang.org/2020/01/03/reducing-support-for-32-bit-apple-targets.html
	cargo +nightly-2020-01-01-x86_64-apple-darwin build --target=armv7-apple-ios --manifest-path=./rust_securerom_payload/Cargo.toml
	ld build/entry.o ./rust_securerom_payload/target/armv7-apple-ios/debug/librust_securerom_payload.a -U _main -U start -static -o build/securerom_payload_packed
	python3 ../../dump_shellcode.py build/securerom_payload_packed build/securerom_payload_shellcode
