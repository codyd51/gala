<div align="center">
  <img src="assets/readme/spread.png" width="60%">
</div>

*gala* is a jailbreak/tethered downgrade tool that currently supports iOS 4. *gala* relies on [limera1n](https://www.theiphonewiki.com/wiki/Limera1n_Exploit) for gaining code execution in SecureROM, then gradually boots and compromises the system under its own steam from there.

*gala* provides the following user-facing features:

* Fully controlled bootchain and IPSW restore process
* Custom boot logos
* Kernel task can be controlled (`task_for_pid(0)`)
* Neutered sandbox
* Neutered code signing
* Any task can be root (`suser() == 0`)
* Enable `/dev/kmem` device file
* Disable FreeBSD MAC enforcement
* Allow RWX pages

A typical tethered jailbreak/restore will go through a process similar to the following:

<table align="center"> 
  <tr>
    <td>
        <img src="assets/readme/runner.png" width="500px"/>
    </td>
  </tr>
  <tr>
      <td><img src="assets/readme/ibss_background.png" width="200px"/></td>
      <td><img src="assets/readme/flashing_filesystem.png" width="200px"/></td>
      <td><img src="assets/readme/jailbroken_with_gala_alert.png" width="200px"/></td>
  </tr>
</table>

*gala* is also a generic patching framework that emphasises maintainable and understandable patch sets. For example, here's how patching a specific instruction sequence looks:

```python
    InstructionPatch(
        function_name="platform_early_init",
        reason="""
        The original logic loads a memory word to find the value to pass to debug_enable_uarts(). 
        We always want the debug logs to be emitted, so override the value here.
        """,
        address=VirtualMemoryPointer(0x84010b96),
        orig_instructions=[Instr.thumb("ldrb r0, [r4]")],
        patched_instructions=[Instr.thumb("movs r0, #3")],
    )
```

As a glance, the reader of this patch can clearly see exactly what's being replaced, and why.

The instructions are assembled with an in-house ad-hoc assembler. `InstructionPatch` performs extensive validations to ensure the patch does exactly what's described in the metadata. For example, `InstructionPatch` will validate:

* That the replaced instructions exactly match what's expected in the patch.
* That disassembling the assembled patch instructions exactly matches what's written in the patch (in other words, that Capstone confirms that the in-house assembler produces the correct opcodes).
* That the exact correct number of bytes are patched based on the input and output instructions

Disassembly is performed via [Capstone](https://www.capstone-engine.org).

Here's what injecting a shellcode program looks like:

```python
shellcode_addr = VirtualMemoryPointer(0x840000fc)
BlobPatch(
    address=shellcode_addr,
    new_content=(RESOURCES / "shellcode").read_bytes(),
),
```

_gala_ uses [strongarm](https://github.com/datatheorem/strongarm) for Mach-O parsing (in particular, finding the correct file offset for a given virtual address).

_gala_ also provides `Patch` types that are especially convenient for producing custom iOS distributions. For example, it's straightforward to patch files that only exist within a mounted `.dmg`:

```python
DmgPatchSet([
    DmgReplaceFileContentsPatch(
        file_path=Path("/private/etc/fstab"),
        new_content="""
/dev/disk0s1 / hfs rw 0 1
/dev/disk0s2s1 /private/var hfs rw,nosuid,nodev 0 2
    """.encode()
    ),
    DmgApplyTarPatch(
        tar_path=_RESOURCES / "ssh_additions.tar"
    ),
])
```

# Requirements

PT: Perhaps clone sshpass and dpkg as tools/?

* sshpass
* 
