@constants -----------------------------------
.pool
@ usb_wait_for_image call offset
.set	RET_ADDR,			0x7ef	@ A4
@.set	RET_ADDR,			0x8b7	@ iPod 3G
@.set	RET_ADDR,			0x8b7	@ iPhone 3Gs new bootrom

.set	loadaddr,			0x84000000
.set	maxsize,			0x24000
.set	dumpaddr,			0x0
.set	dumpto,				0x84000000
.set	dumpsize,			0x10000
.text
@main code -----------------------------------
.code 16
_start: .global _start
	B	entry_point
	NOP
	NOP
	NOP
	NOP
	NOP
	NOP
	NOP
	NOP
	NOP

entry_point:
	LDR	R0,	=dumpto
	LDR	R1,	=dumpaddr
	LDR	R2,	=dumpsize
	BL	memcpy

	LDR	R0,	=loadaddr
	LDR	R1,	=maxsize
	MOV	R2,	#0	
	LDR	R3,	=RET_ADDR
	BLX	R3
@-----------------------------------------------------
memcpy:

_memcpy_loop:
        LDRB     R3,     [R1]
        STRB     R3,     [R0]
        ADD     R0,     #1
        ADD     R1,     #1
        SUB     R2,     #1
        CMP     R2,     #0
        BNE     _memcpy_loop

        BX      LR
@-----------------------------------------------------
.end

