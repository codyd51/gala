.text

.pool
@ usb_wait_for_image call offset
@ A4 only
.set    RET_ADDR,            0x7ef
@.set    RET_ADDR,           0x4c85
.set    loadaddr,            0x84000000
.set    maxsize,            0x24000

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
    adr r0, pwned_serial
    mov r1, pwned_serial_len
    BL _c_entry_point

@loop:
@    bl loop

    LDR    R0,    =loadaddr
    LDR    R1,    =maxsize
    MOV    R2,    #0    
    LDR    R3,    =RET_ADDR
    BLX    R3

.align 2
pwned_serial:
.asciz "[Overwritten serial number!]"
@pwned_serial_len:
@ .equ . - pwned_serial
pwned_serial_len = . - pwned_serial

