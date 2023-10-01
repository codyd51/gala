from strongarm.macho import VirtualMemoryPointer

from gala.assemble import Instr
from gala.configuration import GALA_ROOT
from gala.configuration import GalaConfig
from gala.patch_types import BlobPatch
from gala.patch_types import InstructionPatch
from gala.patch_types import Patch
from gala.patch_types import PatchSet


def get_kernelcache_patches(_config: GalaConfig) -> list[Patch]:
    sandbox_callbacks_start = 0x803C5A40
    sandbox_callbacks_end = 0x803C5F20
    zero_fill = b"\0" * (sandbox_callbacks_end - sandbox_callbacks_start)
    sandbox_blob_patch = BlobPatch(address=VirtualMemoryPointer(sandbox_callbacks_start), new_content=zero_fill)
    sandbox_patch = PatchSet(
        name="Neuter sandbox",
        patches=[
            sandbox_blob_patch,
            InstructionPatch(
                function_name="sandbox_mac_policy_register",
                reason="""
                    This function calls mac_policy_register to register the sandbox with the MAC subsystem. By eliding
                    this call, the sandbox will never be hooked up to MAC.
                """,
                address=VirtualMemoryPointer(0x803C445E),
                orig_instructions=[Instr.thumb("blx r3")],
                patched_instructions=[Instr.thumb_nop()],
            ),
            InstructionPatch(
                function_name="sandbox_register_mac_policy_and_store",
                reason="""
                    Elide the branch to sandbox_mac_policy_register() so that the sandbox never gets hooked up to MAC.
                """,
                address=VirtualMemoryPointer(0x803C100A),
                orig_instructions=[Instr.thumb("blx r3")],
                patched_instructions=[Instr.thumb("movs r0, #0")],
            ),
        ],
    )
    setuid_patch = PatchSet(
        name="Everyone is root",
        patches=[
            InstructionPatch(
                address=VirtualMemoryPointer(0x8014C696),
                function_name="suser",
                reason="""
                    Checks the return value of kauth_cred_getuid().
                    If we're not UID 0, returns zero. 
                    Let's pretend we're always UID 0.
                """,
                orig_instructions=[Instr.thumb("cbnz r0, #0x8014c6a4")],
                patched_instructions=[Instr.thumb("movs r0, #0")],
            )
        ],
    )

    neuter_amfi = PatchSet(
        name="Neuter AMFI",
        patches=[
            # PT: Can't patch this because it's in __common,__DATA,
            # bss which takes up no space on disk (and takes up zero space in the file/has zero
            # 'file data' -- Hopper 'magically' shows XRefs to this region)
            # PE_i_can_has_debugger
            # PT: We might need a shellcode program that sets that var to 1, but how to run it at startup?
            BlobPatch(
                address=VirtualMemoryPointer(0x80966080),
                new_content=(
                    GALA_ROOT
                    / "shellcode_programs"
                    / "kernelcache_set_debug_enabled"
                    / "build"
                    / "kernelcache_set_debug_enabled_shellcode"
                ).read_bytes(),
            ),
            # PT: Our in-house assembler doesn't support the backwards far branch we need here
            # This disassembles to "bl 0x80966080" (the shellcode program we injected above).
            # We're replacing a call to printf() with a call to the shellcode program above, which will set the
            # *debug_enabled static variable.
            BlobPatch(address=VirtualMemoryPointer(0x801D5BEA), new_content=bytes([0x90, 0xF3, 0x49, 0xF2])),
            # PT: The following patches may no longer be necessary
            InstructionPatch(
                function_name="AppleMobileFileIntegrity::start",
                reason="""
                    The original code conditionally branches away based on the value of _PE_i_can_has_debugger. 
                    Always stay here, as though _PE_i_can_has_debugger is set.
                """,
                address=VirtualMemoryPointer(0x803AAEB2),
                orig_instructions=[Instr.thumb("beq #0x803aaf3a")],
                patched_instructions=[Instr.thumb_nop()],
            ),
            InstructionPatch(
                function_name="AppleMobileFileIntegrity::start",
                reason="""
                    The basic block checks whether a boot argument has disabled code signature enforcement.
                    Nudge things such that we're always on the code path for disabled code signature enforcement.
                """,
                address=VirtualMemoryPointer(0x803AAEF4),
                orig_instructions=[Instr.thumb("beq #0x803aaf00")],
                patched_instructions=[Instr.thumb_nop()],
            ),
            InstructionPatch(
                function_name="AppleMobileFileIntegrity::start",
                reason="""
                    The basic block checks whether a boot argument has disabled code signature enforcement.
                    Nudge things such that we're always on the code path for disabled code signature enforcement.
                """,
                address=VirtualMemoryPointer(0x803AAF14),
                orig_instructions=[Instr.thumb("beq #0x803aaf20")],
                patched_instructions=[Instr.thumb_nop()],
            ),
            InstructionPatch(
                function_name="AppleMobileFileIntegrity::start",
                reason="""
                    The basic block checks whether a boot argument has disabled cs_enforcement.
                    Nudge things such that we're always on the code path for disabled cs_enforcement.
                """,
                address=VirtualMemoryPointer(0x803AAF28),
                orig_instructions=[Instr.thumb("cbz r0, #0x803aaf3c")],
                patched_instructions=[Instr.thumb_nop()],
            ),
            InstructionPatch(
                function_name="AppleMobileFileIntegrity::start",
                reason="""
                    There's a conditional branch here for "outside of container && !i_can_has_debugger". 
                    Always avoid the failure branch.
                """,
                address=VirtualMemoryPointer(0x803C4540),
                orig_instructions=[Instr.thumb("cbz r0, #0x803c454a")],
                patched_instructions=[Instr.thumb("b #0x803c454a")],
            ),
        ],
    )

    image3_nor_patch_reason = "Image3 tags are checked when flashing images to NOR, so neuter these comparisons"
    disable_image3_nor_signature_checks = PatchSet(
        name="NOR access will accept an unpersonalized Image3",
        patches=[
            InstructionPatch(
                function_name="validate_image3",
                reason=image3_nor_patch_reason,
                address=VirtualMemoryPointer(cmp_address),
                orig_instructions=[Instr.thumb(orig_instr)],
                patched_instructions=[Instr.thumb("cmp r0, r0")],
            )
            for cmp_address, orig_instr in [
                (0x8057C800, "cmp r0, #0"),
                # 'SHSH' tag
                (0x8057C7E4, "cmp r0, #0"),
                (0x8057C7F2, "cmp r0, #0"),
                # 'illb' tab
                (0x8057C826, "cmp r3, r2"),
                (0x8057C876, "cmp r0, #0"),
                # 'DATA' tag
                (0x8057C88A, "cmp r0, #0"),
            ]
        ],
    )

    disable_more_signature_checks = PatchSet(
        name="Neuter AMFI TrustCache signature checks",
        patches=[
            InstructionPatch(
                function_name="rsa_check",
                reason="""Patch out the call to an inner validation routine and make it look like it succeeded.""",
                address=VirtualMemoryPointer(0x8057D452),
                orig_instructions=[Instr.thumb("mov r4, r0"), Instr.thumb("b #0x8057d458")],
                patched_instructions=[Instr.thumb("movs r0, #0"), Instr.thumb("movs r0, #0")],
            ),
            InstructionPatch(
                function_name="amfi_validate_img3",
                reason="Patch the comparison when validating the SHSH tag of the trust cache",
                address=VirtualMemoryPointer(0x803AC4FE),
                orig_instructions=[Instr.thumb("cmp r3, r2")],
                patched_instructions=[Instr.thumb("cmp r0, r0")],
            ),
            InstructionPatch(
                function_name="amfi_validate_img3",
                reason="Patch the comparison when validating the CERT tag of the trust cache",
                address=VirtualMemoryPointer(0x803AC560),
                orig_instructions=[Instr.thumb("cmp r3, r2")],
                patched_instructions=[Instr.thumb("cmp r0, r0")],
            ),
            InstructionPatch(
                function_name="AppleMobileFileIntegrity::loadTrustCache",
                reason="Patch another SHSH tag check of the trust cache. Branch unconditionally to the success path.",
                address=VirtualMemoryPointer(0x803AA8C0),
                orig_instructions=[Instr.thumb("mov r2, r0"), Instr.thumb("cbz r0, #0x803aa8ce")],
                patched_instructions=[Instr.thumb("cmp r0, r0"), Instr.thumb("b #0x803aa8ce")],
            ),
            InstructionPatch(
                function_name="AppleMobileFileIntegrity::loadTrustCache",
                reason="Don't branch away when the 'trst' tag comparison fails.",
                address=VirtualMemoryPointer(0x803AA904),
                orig_instructions=[Instr.thumb("bne #0x803aa8c6")],
                patched_instructions=[Instr.thumb_nop()],
            ),
        ],
    )

    enable_task_for_pid_0 = PatchSet(
        name="Enable task_for_pid(0)",
        patches=[
            InstructionPatch(
                address=VirtualMemoryPointer(0x8017E552),
                function_name="task_for_pid",
                reason="""
                    This is an early-return to prevent task_for_pid() 
                    returning a real answer for PID 0.
                    This code stays on a failure path if the provided PID is 0. 
                    We always want to branch away to the success path, 
                    which proceeds with the task_for_pid() call.
                """,
                orig_instructions=[Instr.thumb("cbnz r4, #0x8017e56c")],
                patched_instructions=[Instr.thumb("b #0x8017e56c")],
            ),
        ],
    )

    # http://www.it-docs.net/ddata/781.pdf
    sandbox_debug_mode = PatchSet(
        name="SandboxDebugMode",
        patches=[
            InstructionPatch(
                address=VirtualMemoryPointer(0x803C4578),
                function_name="hook..execve",
                reason="""
                    The code just above fetches a value from the sandbox policy, then conditionally branches away. 
                    Ensure we always stay on this path.
                    The original instruction is a 4-byte Thumb instruction, so snug in an extra nop.
                """,
                orig_instructions=[Instr.thumb("tst.w r0, #4")],
                patched_instructions=[Instr.thumb("movs r3, #1"), Instr.thumb_nop()],
                expected_length=4,
            ),
        ],
    )

    disable_mac_enforcement = PatchSet(
        name="Disable MAC enforcement",
        patches=[
            BlobPatch(VirtualMemoryPointer(addr), new_content=int(0).to_bytes(4, byteorder="little"))
            for addr in [
                0x8025EF80,
                0x8025F188,
            ]
        ],
    )

    allow_rwx_pages = PatchSet(
        name="Allow RWX pages",
        patches=[
            InstructionPatch(
                function_name="vm_map_protect",
                reason="""
                    The basic block containing this instruction is reached from a "tst VM_PROT_EXECUTE bit" branch.
                    The original instruction here clears the VM_PROT_EXECUTE bit. 
                    In other words, the original code is a safety check that nips away the VM_PROT_EXECUTE bit.
                    Defang it so VM_PROT_EXECUTE can stay.
                """,
                address=VirtualMemoryPointer(0x8003D9FC),
                orig_instructions=[Instr.thumb("bic r5, r5, #4")],
                patched_instructions=[Instr.thumb_nop(), Instr.thumb_nop()],
                expected_length=4,
            ),
            InstructionPatch(
                function_name="vm_map_enter",
                reason="""
                    Same concept as our vm_map_protect patch on VM_PROT_EXECUTE, but in vm_map_enter.
                    Defang the safety check so VM_PROT_EXECUTE can stay.
                """,
                address=VirtualMemoryPointer(0x800409E8),
                orig_instructions=[Instr.thumb("bic r6, r6, #4")],
                patched_instructions=[Instr.thumb_nop(), Instr.thumb_nop()],
                expected_length=4,
            ),
            InstructionPatch(
                function_name="vm_map_enter",
                reason="""
                    The original code branches away into several safety checks if VM_PROT_WRITE is set.
                    Neuter this branch away so the code never even tries to validate things.
                """,
                address=VirtualMemoryPointer(0x80040976),
                orig_instructions=[Instr.thumb("bne #0x800409da")],
                patched_instructions=[Instr.thumb_nop()],
            ),
        ],
    )

    neuter_firmware_download_timer = InstructionPatch(
        function_name="wlan_check_if_timeout_reached",
        reason="""
            When iOS boots up with gala, a message is eventually visible in the logs: 
            "Error, no successful firmware download after %ld ms!! Giving up..."
            The code appears to be a WLAN chip driver.
            This doesn't appear to have any adverse affects, but seems a bit spooky, so let's have some fun by 
            neutering it. In this case, there's a conditional branch checking whether the timer limit has been reached.
            Patch the branch so it looks like the timer is never ready to fire.
        """,
        address=VirtualMemoryPointer(0x8080E826),
        orig_instructions=[Instr.thumb("bne #0x8080e85a")],
        patched_instructions=[Instr.thumb("b #0x8080e85a")],
    )

    return [
        neuter_amfi,
        neuter_firmware_download_timer,
        disable_image3_nor_signature_checks,
        disable_more_signature_checks,
        setuid_patch,
        sandbox_patch,
        enable_task_for_pid_0,
        disable_mac_enforcement,
        sandbox_debug_mode,
        allow_rwx_pages,
    ]
