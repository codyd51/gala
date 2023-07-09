@constants -----------------------------------
.pool
@ usb_wait_for_image call offset
@ A4 only
.set	RET_ADDR,			0x7ef
.set	loadaddr,			0x84000000
.set	maxsize,			0x24000
.text
@main code -----------------------------------
.extern _c_entry_point
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
    BL _c_entry_point

    LDR    R0,    =loadaddr
    LDR    R1,    =maxsize
    MOV    R2,    #0    
    LDR    R3,    =RET_ADDR
    BLX    R3

.end
