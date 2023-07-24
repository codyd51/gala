idevicerestore ) ./src/idevicerestore --restore-mode "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped"
idevicerestore 1.0.0-135-g609f7f0
client mode Unknown
Found device in Restore mode
INFO: device serial number is 84033X5RA4S
ECID: 3727865267063
Identified device as n90ap, iPhone3,1
Extracting BuildManifest from IPSW
Product Version: 4.0
Product Build: 8A293 Major: 8
Device supports Image4: false
Variant: Customer Upgrade Install (IPSW)
This restore will update the device without erasing user data.
Checking IPSW for required components...
All required components found in IPSW
Using cached filesystem from '/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/018-6303-385.dmg'
ERROR: Unable to proceed without a TSS record.
idevicerestore ) ./src/idevicerestore --restore-mode "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped"
idevicerestore 1.0.0-135-g609f7f0
client mode Unknown
Found device in Restore mode
INFO: device serial number is 84033X5RA4S
ECID: 3727865267063
Identified device as n90ap, iPhone3,1
Extracting BuildManifest from IPSW
Product Version: 4.0
Product Build: 8A293 Major: 8
Device supports Image4: false
Variant: Customer Upgrade Install (IPSW)
This restore will update the device without erasing user data.
Checking IPSW for required components...
All required components found in IPSW
Using cached filesystem from '/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/018-6303-385.dmg'
ERROR: Unable to proceed without a TSS record.
idevicerestore ) make
/Applications/Xcode-beta.app/Contents/Developer/usr/bin/make  all-recursive
Making all in src
CC       idevicerestore-idevicerestore.o
CCLD     idevicerestore
Making all in docs
make[2]: Nothing to be done for `all'.
make[2]: Nothing to be done for `all-am'.
idevicerestore ) ./src/idevicerestore --restore-mode "/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped"
idevicerestore 1.0.0-135-g609f7f0
client mode Unknown
Found device in Restore mode
INFO: device serial number is 84033X5RA4S
ECID: 3727865267063
Identified device as n90ap, iPhone3,1
Extracting BuildManifest from IPSW
Product Version: 4.0
Product Build: 8A293 Major: 8
Device supports Image4: false
Variant: Customer Upgrade Install (IPSW)
This restore will update the device without erasing user data.
Checking IPSW for required components...
All required components found in IPSW
Using cached filesystem from '/Users/philliptennen/Documents/Jailbreak/ipsw/iPhone3,1_4.0_8A293_Restore.ipsw.unzipped/018-6303-385.dmg'
About to restore device...
Connecting now...
Connected to com.apple.mobile.restored, version 12
Device 8e8366ad7bf1222351522c423aea5fecc9e62793 has successfully entered restore mode
Hardware Information:
BoardID: 0
ChipID: 35120
UniqueChipID: 3727865267063
ProductionMode: true
Starting Reverse Proxy
Could not create Reverse Proxy
Waiting for NAND (28)
Creating partition map (11)
Creating filesystem (12)
Creating filesystem (12)
About to send filesystem...
Connected to ASR
Validating the filesystem
Filesystem validated
Sending filesystem now...
[==================================================] 100.0%
Done sending filesystem
Verifying restore (14)
[==================================================] 100.0%
Checking filesystems (15)
Mounting filesystems (16)
Checking filesystems (15)
Mounting filesystems (16)
About to send KernelCache...
Extracting kernelcache.release.n90 (kernelcache.release.n90)...
Not personalizing component KernelCache...
Sending KernelCache now...
Done sending KernelCache
Installing kernelcache (27)
Fixing up /var (17)
Modifying persistent boot-args (25)
About to send NORData...
Found firmware path Firmware/all_flash/all_flash.n90ap.production
Getting firmware manifest from Firmware/all_flash/all_flash.n90ap.production/manifest
Extracting LLB.n90ap.RELEASE.img3 (Firmware/all_flash/all_flash.n90ap.production/LLB.n90ap.RELEASE.img3)...
Not personalizing component LLB...
Extracting iBoot.n90ap.RELEASE.img3 (Firmware/all_flash/all_flash.n90ap.production/iBoot.n90ap.RELEASE.img3)...
Not personalizing component iBoot...
Extracting DeviceTree.n90ap.img3 (Firmware/all_flash/all_flash.n90ap.production/DeviceTree.n90ap.img3)...
Not personalizing component DeviceTree...
Extracting applelogo-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/applelogo-640x960.s5l8930x.img3)...
Not personalizing component AppleLogo...
Extracting recoverymode-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/recoverymode-640x960.s5l8930x.img3)...
Not personalizing component RecoveryMode...
Extracting batterylow0-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/batterylow0-640x960.s5l8930x.img3)...
Not personalizing component BatteryLow0...
Extracting batterylow1-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/batterylow1-640x960.s5l8930x.img3)...
Not personalizing component BatteryLow1...
Extracting glyphcharging-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/glyphcharging-640x960.s5l8930x.img3)...
Not personalizing component BatteryCharging...
Extracting glyphplugin-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/glyphplugin-640x960.s5l8930x.img3)...
Not personalizing component BatteryPlugin...
Extracting batterycharging0-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/batterycharging0-640x960.s5l8930x.img3)...
Not personalizing component BatteryCharging0...
Extracting batterycharging1-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/batterycharging1-640x960.s5l8930x.img3)...
Not personalizing component BatteryCharging1...
Extracting batteryfull-640x960.s5l8930x.img3 (Firmware/all_flash/all_flash.n90ap.production/batteryfull-640x960.s5l8930x.img3)...
Not personalizing component BatteryFull...
Sending NORData now...
Done sending NORData
Flashing firmware (18)
Got status message
Unhandled status message (37)
common.c:printing 32409 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>AMRError</key>
        <integer>37</integer>
        <key>Log</key>
        <string> ARM Device=uart2 at 0x82700000(0xd2c26000)
AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart3 at 0x82800000(0xd2c35000)
AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart6 at 0x82b00000(0xd2c7d000)
[000000.372690]: AppleSamsungDPTXController::disableInterrupts: disabling
[000000.000042]: AppleSamsungDPTXController::disableInterrupts: _outstandingIO=0 _pendingDisable=0
HighlandParkAudioDevice::start: 0x82063000, highland-park mIICNub: 0x81e19e00, mIISNub: 0x8243fe80, mSerialNub: 0x82442200, sampleRate = 44100, ol=8, oi=7
AppleAP3GDL::probe found device with ID: 0xd3
AppleAP3GDL::handleStart _calibrationMatrix [63663 -29 -193] [669 61250 146] [64 -381 65310]
AppleAP3GDL::handleStart _calibrationInverseMatrix [67463 33 198] [-736 70121 -158] [-69 408 65762]
AppleBaseband: inconsistent mux function setup (0 0 0 0 0 0)
AppleNANDFTL started with IOFlashStoragePartition provider
AppleNANDFTL located at physical nand block offset 16
metadata-whitening was found and it's set to 1
default-ftl-version was found and it's set to 1
diag-bits is supplied by AppleNANDFTL
[FTL:MSG] Apple NAND Driver (AND) RW
[FTL:MSG] FIL_Init            [OK]
[FTL:MSG] BUF_Init            [OK]
[FTL:MSG] FPart Init          [OK]
AppleMultitouchN1SPI: successfully started
AppleMultitouchN1SPI: using DMA for bootloading
AppleMultitouchN1SPI: Logging is ENABLED
virtual bool AppleCLCD::start_hardware(IOService*), ditherCfg: 0x80000001 mIsDitherFor8Bits: 1
IOReturn AppleCLCD::set_ditherTable_state(bool), mIsDitherFor8Bits is true, no dynamic dither table.
IOSurface: buffer allocation size is zero
AppleM2ScalerCSCDriver: Added framebuffer device: AppleCLCD  id: c8124000
AppleRGBOUT: TVOUT device is detected
AppleD1815PMUPowerSource: AppleUSBCableDetect 1
AppleD1815PMUPowerSource: AppleUSBCableType USBHost
AppleEmbeddedUSBArbitrator::_usbCableTypeNotificationGated : cableType: USBHost
AppleEmbeddedUSBArbitrator::handleUSBCableTypeChange : Connected to a USB Host
AppleEmbeddedUSBNub::withProvider : allocated new nub 0x82827d00
AppleEmbeddedUSBNub::initWithProvider : finished nub init
AppleEmbeddedUSBArbitrator::_publishNubs : nub published
AppleSynopsysOTGDevice::init : Logging Buffer Length = 4K
AppleSynopsysOTGDevice::start : object is 0x825e9000, registers at 0xd3bc2000, 0x86100000 physical
AppleSynopsysOTGDevice::findMaxEndpoints: in EPs: 7, out EPs: 7, max_endpoint: 8, num_endpoints: 14 
AppleSynopsysOTGDevice::handleUSBCableConnect cable connected, but don't have device configuration yet
AppleSynopsysOTGDevice::start : start finished
AppleMultitouchN1SPI: detected HBPP. driver will be kept alive
IOSDIOController::enumerateSlot(): Searching for SDIO device in slot: 0
IOSDIOController::enumerateSlot(): Found SDIO I/O device. Function count(1), memory(0)
AppleEmbeddedUSBArbitrator::_usbCableTypeNotificationGated : cableType: USBHost
AppleS5L8930XUSBArbitrator::handleUSBCableTypeChange : no change in cable-type
IOSDIOIoCardDevice::parseFn0CIS(): Device manufacturer ID 0x2d0, Product ID 0x4329
IOSDIOIoCardDevice::parseFn0CIS(): Manufacturer: ""
IOSDIOIoCardDevice::parseFn0CIS(): Product:      ""
IOSDIOIoCardDevice::parseFn0CIS(): ProductInfo0: "s=B1"
IOSDIOIoCardDevice::parseFn0CIS(): ProductInfo1: "P=N90 m=3.1 V=u"
AppleBCMWLAN::init(): AppleBCMWLAN-42 May 26 2010 22:44:52
AppleBCMWLAN::init(): Starting with debug level: 4, debug flags: 00000000
AppleBCMWLAN::init(): AppleBCMWLAN-42 May 26 2010 22:44:52
AppleBCMWLAN::init(): Starting with debug level: 4, debug flags: 00000000
found suitable IOMobileFramebuffer: AppleCLCD
display-scale = 2
display-rotation = 0
found PTP interface
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49152
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49153
recv(11, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49154
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49155
recv(14, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49157
recv(17, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49158
recv(9, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49156
recv(9, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49161
recv(17, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49163
recv(20, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49159
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49160
Result new session 0x83f8ef80 established 62078&lt;-lo0-&gt;49161 62078&lt;-usb-&gt;55852
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078&lt;-lo0-&gt;49162 62078&lt;-usb-&gt;56108
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed80 established 62078&lt;-lo0-&gt;49163 62078&lt;-usb-&gt;56364
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078&lt;-lo0-&gt;49164 62078&lt;-usb-&gt;56620
AppleUSBDeviceMux::handleConnectResult new session 0x82570b80 established 62078&lt;-lo0-&gt;49165 62078&lt;-usb-&gt;56876
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed80
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570b00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed80 established 62078&lt;-lo0-&gt;49166 62078&lt;-usb-&gt;57132
AppleUSBDeviceMux::handleConnectResult new session 0x82570b00 established 62078&lt;-lo0-&gt;49167 62078&lt;-usb-&gt;57388
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570b80
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
AppleUSBDeviceMux::handleConnectResult new session 0x82570b80 established 62078&lt;-lo0-&gt;49168 62078&lt;-usb-&gt;57644
recv(13, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49165
recv(12, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49162
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49167
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49169
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49170
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49171
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49172
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49173
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49174
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49175
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49176
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49177
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49178
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49179
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49180
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49181
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49182
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49183
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49184
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49185
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49186
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49187
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49188
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49189
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49190
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49191
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49192
 closing 0x82570a00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49190 62078&lt;-usb-&gt;63276
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49191 62078&lt;-usb-&gt;63532
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49192 62078&lt;-usb-&gt;63788
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleBCMWLAN::handleIOKitBusyWatchdogTimeout(): Error, no successful firmware download after 60000 ms!! Giving up...
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49193 62078&lt;-usb-&gt;64044
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49193
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49194 62078&lt;-usb-&gt;64300
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49194
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49195 62078&lt;-usb-&gt;64556
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49195
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49196
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49196 62078&lt;-usb-&gt;64812
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49197 62078&lt;-usb-&gt;65068
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49197
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49198 62078&lt;-usb-&gt;65324
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49198
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49199 62078&lt;-usb-&gt;45
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49199
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49200
close(caller = 0x5695): remote port = 49202
recv(11, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49201
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49200 62078&lt;-usb-&gt;301
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49201 62078&lt;-usb-&gt;557
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49202 62078&lt;-usb-&gt;813
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
recv(9, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49164
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
close(caller = 0x5695): remote port = 49203
close(caller = 0x5695): remote port = 49205
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49204
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49203 62078&lt;-usb-&gt;1069
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078&lt;-lo0-&gt;49204 62078&lt;-usb-&gt;1325
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef00 established 62078&lt;-lo0-&gt;49205 62078&lt;-usb-&gt;1581
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
close(caller = 0x5695): remote port = 49206
close(caller = 0x5695): remote port = 49208
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49207
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef00 established 62078&lt;-lo0-&gt;49206 62078&lt;-usb-&gt;1837
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49207 62078&lt;-usb-&gt;2093
AppleUSBDeviceMux::sessionUpcall socket is closed, session 0x83f8ef00 (62078&lt;-lo0-&gt;49206 62078&lt;-usb-&gt;1837)
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078&lt;-lo0-&gt;49208 62078&lt;-usb-&gt;2349
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49209
close(caller = 0x5695): remote port = 49211
close(caller = 0x5695): remote port = 49212
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49210
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078&lt;-lo0-&gt;49209 62078&lt;-usb-&gt;2605
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49210 62078&lt;-usb-&gt;2861
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49211 62078&lt;-usb-&gt;3117
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49212 62078&lt;-usb-&gt;3373
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49213
close(caller = 0x5695): remote port = 49215
close(caller = 0x5695): remote port = 49216
close(caller = 0x5695): remote port = 49217
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49214
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49213 62078&lt;-usb-&gt;3629
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49214 62078&lt;-usb-&gt;3885
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed00 established 62078&lt;-lo0-&gt;49215 62078&lt;-usb-&gt;4141
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed00
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078&lt;-lo0-&gt;49216 62078&lt;-usb-&gt;4397
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078&lt;-lo0-&gt;49217 62078&lt;-usb-&gt;4653
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49218
close(caller = 0x5695): remote port = 49220
close(caller = 0x5695): remote port = 49221
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49219
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078&lt;-lo0-&gt;49218 62078&lt;-usb-&gt;4909
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49219 62078&lt;-usb-&gt;5165
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed00 established 62078&lt;-lo0-&gt;49220 62078&lt;-usb-&gt;5421
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49221 62078&lt;-usb-&gt;5677
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49222
close(caller = 0x5695): remote port = 49224
close(caller = 0x5695): remote port = 49225
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49223
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49222 62078&lt;-usb-&gt;5933
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49223 62078&lt;-usb-&gt;6189
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49224 62078&lt;-usb-&gt;6445
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49225 62078&lt;-usb-&gt;6701
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49226
close(caller = 0x5695): remote port = 49228
close(caller = 0x5695): remote port = 49229
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49227
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49226 62078&lt;-usb-&gt;6957
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49227 62078&lt;-usb-&gt;7213
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49228 62078&lt;-usb-&gt;7469
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078&lt;-lo0-&gt;49229 62078&lt;-usb-&gt;7725
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49230
close(caller = 0x5695): remote port = 49232
close(caller = 0x5695): remote port = 49233
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49231
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078&lt;-lo0-&gt;49230 62078&lt;-usb-&gt;7981
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49231 62078&lt;-usb-&gt;8237
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078&lt;-lo0-&gt;49232 62078&lt;-usb-&gt;8493
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed00 established 62078&lt;-lo0-&gt;49233 62078&lt;-usb-&gt;8749
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49234
close(caller = 0x5695): remote port = 49236
close(caller = 0x5695): remote port = 49237
close(caller = 0x5695): remote port = 49238
client protocol version 12
Restore options:
        SystemPartitionSize            =&gt; &lt;CFNumber 0xb0bbd0 [0x1a9d5c]&gt;{value = +1024, type = kCFNumberSInt64Type}
entering partition_nand_device
device supports boot-from-NAND
nand device is already partitioned
entering wait_for_storage_device
entering format_effaceable_storage
effaceable storage is formatted, clearing it
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed00 established 62078&lt;-lo0-&gt;49234 62078&lt;-usb-&gt;9005
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078&lt;-lo0-&gt;49235 62078&lt;-usb-&gt;9261
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49236 62078&lt;-usb-&gt;9517
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078&lt;-lo0-&gt;49237 62078&lt;-usb-&gt;9773
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078&lt;-lo0-&gt;49238 62078&lt;-usb-&gt;10029
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078&lt;-lo0-&gt;49239 62078&lt;-usb-&gt;10285
void AppleUSBDeviceMux::handleConnectResult(BulkUSBMuxSession*, errno_t) new session to port 1082 failed: 61
effaceable storaged cleared
entering check_for_restore_log
could not find partition, unable to check for restore log
entering create_filesystem_partitions
NAND format complete
creating encrypted data partition
wipe entire partition: 1 (old = 0 new = 1024)
block size for /dev/disk0s1: 8192
/sbin/newfs_hfs -s -v System -b 8192 -n a=8192,c=8192,e=8192 /dev/disk0s1 
executing /sbin/newfs_hfs
Initialized /dev/rdisk0s1 as a 1024 MB HFS Plus volume
block size for /dev/disk0s2s1: 8192
/sbin/newfs_hfs -s -v Data -J -P -b 8192 -n a=8192,c=8192,e=8192 /dev/disk0s2s1 
executing /sbin/newfs_hfs
Initialized /dev/rdisk0s2s1 as a 14 GB HFS Plus volume with a 8192k journal
entering restore_images
executing /usr/sbin/asr
void AppleUSBDeviceMux::handleConnectResult(BulkUSBMuxSession*, errno_t) new session to port 12345 failed: 61
ASR STATUS: start       223     multicast-client
ASR: Waiting for connection attempt from server
ASR STATUS: setup
ASR: Validating target...
ASR: done
ASR STATUS: metadata
ASR: Validating source...
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 12345&lt;-lo0-&gt;49242 12345&lt;-usb-&gt;11053
ASR: Using Hardware AES
ASR: Using Hardware AES
ASR: Using Hardware AES
ASR: done
ASR: Using Hardware AES
ASR: Warning: You may not be able to start up a computer with the target volume.
ASR: Retrieving scan information...done
ASR: Validating sizes...
ASR: done
ASR STATUS: restore
ASR RESTORE PROGRESS: 2%
ASR RESTORE PROGRESS: 4%
ASR RESTORE PROGRESS: 6%
ASR RESTORE PROGRESS: 8%
ASR RESTORE PROGRESS: 10%
ASR RESTORE PROGRESS: 12%
ASR RESTORE PROGRESS: 14%
ASR RESTORE PROGRESS: 16%
ASR RESTORE PROGRESS: 18%
ASR RESTORE PROGRESS: 20%
ASR RESTORE PROGRESS: 22%
ASR RESTORE PROGRESS: 24%
ASR RESTORE PROGRESS: 26%
ASR RESTORE PROGRESS: 28%
ASR RESTORE PROGRESS: 30%
ASR RESTORE PROGRESS: 32%
ASR RESTORE PROGRESS: 34%
ASR RESTORE PROGRESS: 36%
ASR RESTORE PROGRESS: 38%
ASR RESTORE PROGRESS: 40%
ASR RESTORE PROGRESS: 42%
recv(18, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49243
recv(18, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49244
recv(18, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49245
ASR RESTORE PROGRESS: 44%
AppleUSBDeviceMux::handleConnectResult new session 0x84215800 established 62078&lt;-lo0-&gt;49243 62078&lt;-usb-&gt;11309
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x84215800
AppleUSBDeviceMux::handleConnectResult new session 0x84215780 established 62078&lt;-lo0-&gt;49244 62078&lt;-usb-&gt;11565
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x84215780
AppleUSBDeviceMux::handleConnectResult new session 0x84215800 established 62078&lt;-lo0-&gt;49245 62078&lt;-usb-&gt;11821
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x84215800
ASR RESTORE PROGRESS: 46%
ASR RESTORE PROGRESS: 48%
ASR RESTORE PROGRESS: 50%
ASR RESTORE PROGRESS: 52%
ASR RESTORE PROGRESS: 54%
ASR RESTORE PROGRESS: 56%
ASR RESTORE PROGRESS: 58%
ASR RESTORE PROGRESS: 60%
ASR RESTORE PROGRESS: 62%
ASR RESTORE PROGRESS: 64%
ASR RESTORE PROGRESS: 66%
ASR RESTORE PROGRESS: 68%
ASR RESTORE PROGRESS: 70%
ASR RESTORE PROGRESS: 72%
ASR RESTORE PROGRESS: 74%
ASR RESTORE PROGRESS: 76%
ASR RESTORE PROGRESS: 78%
ASR RESTORE PROGRESS: 80%
ASR RESTORE PROGRESS: 82%
ASR RESTORE PROGRESS: 84%
ASR RESTORE PROGRESS: 86%
ASR RESTORE PROGRESS: 88%
ASR RESTORE PROGRESS: 90%
ASR RESTORE PROGRESS: 92%
ASR RESTORE PROGRESS: 94%
ASR RESTORE PROGRESS: 96%
ASR RESTORE PROGRESS: 98%
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
ASR RESTORE PROGRESS: 100%
ASR: Copied 995688960 bytes in 75.61 seconds, 12859.84 KiB/s
ASR STATUS: verify
ASR VERIFY PROGRESS: 2%
ASR VERIFY PROGRESS: 4%
ASR VERIFY PROGRESS: 6%
ASR VERIFY PROGRESS: 8%
ASR VERIFY PROGRESS: 10%
ASR VERIFY PROGRESS: 12%
ASR VERIFY PROGRESS: 14%
ASR VERIFY PROGRESS: 16%
ASR VERIFY PROGRESS: 18%
ASR VERIFY PROGRESS: 20%
ASR VERIFY PROGRESS: 22%
ASR VERIFY PROGRESS: 24%
ASR VERIFY PROGRESS: 26%
ASR VERIFY PROGRESS: 28%
ASR VERIFY PROGRESS: 30%
ASR VERIFY PROGRESS: 32%
ASR VERIFY PROGRESS: 34%
ASR VERIFY PROGRESS: 36%
ASR VERIFY PROGRESS: 38%
ASR VERIFY PROGRESS: 40%
ASR VERIFY PROGRESS: 42%
ASR VERIFY PROGRESS: 44%
ASR VERIFY PROGRESS: 46%
ASR VERIFY PROGRESS: 48%
ASR VERIFY PROGRESS: 50%
ASR VERIFY PROGRESS: 52%
ASR VERIFY PROGRESS: 54%
ASR VERIFY PROGRESS: 56%
ASR VERIFY PROGRESS: 58%
ASR VERIFY PROGRESS: 60%
ASR VERIFY PROGRESS: 62%
ASR VERIFY PROGRESS: 64%
ASR VERIFY PROGRESS: 66%
ASR VERIFY PROGRESS: 68%
ASR VERIFY PROGRESS: 70%
ASR VERIFY PROGRESS: 72%
ASR VERIFY PROGRESS: 74%
ASR VERIFY PROGRESS: 76%
ASR VERIFY PROGRESS: 78%
ASR VERIFY PROGRESS: 80%
ASR VERIFY PROGRESS: 82%
ASR VERIFY PROGRESS: 84%
ASR VERIFY PROGRESS: 86%
ASR VERIFY PROGRESS: 88%
ASR VERIFY PROGRESS: 90%
ASR VERIFY PROGRESS: 92%
ASR VERIFY PROGRESS: 94%
ASR VERIFY PROGRESS: 96%
ASR VERIFY PROGRESS: 98%
ASR VERIFY PROGRESS: 100%
ASR: Verified SHA-1 checksum 995688960 bytes in 25.93 seconds, 37504.02 KiB/s
ASR STATUS: finish
entering mount_filesystems
executing /sbin/fsck_hfs
** /dev/rdisk0s1
   Executing fsck_hfs (version diskdev_cmds-488.1.7~39).
** Checking non-journaled HFS Plus Volume.
** Detected a case-sensitive volume.
** Checking extents overflow file.
** Checking catalog file.
** Checking multi-linked files.
** Checking catalog hierarchy.
** Checking extended attributes file.
** Checking volume bitmap.
** Checking volume information.
** The volume Apex8A293.N90OS appears to be OK.
executing /sbin/mount
executing /sbin/fsck_hfs
disk0s2s1: ioctl(_IOW,'d',24,4) is unsupported.
** /dev/rdisk0s2s1
   Executing fsck_hfs (version diskdev_cmds-488.1.7~39).
** Checking Journaled HFS Plus volume.
** Detected a case-sensitive volume.
** Checking extents overflow file.
** Checking catalog file.
** Checking multi-linked files.
** Checking catalog hierarchy.
** Checking extended attributes file.
** Checking volume bitmap.
** Checking volume information.
** The volume Data appears to be OK.
executing /sbin/mount
entering install_kernel_cache
writing kernelcache to /mnt1/System/Library/Caches/com.apple.kernelcaches/kernelcache
entering install_secure_vault_daemon
entering get_hardware_platform
platform-name = s5l8930x
linking /mnt1/usr/sbin/securekeyvaultd to /mnt1/usr/sbin/securekeyvaultd.s5l8930x
no securekeyvaultd for s5l8930x
entering fixup_var
remove_path /mnt1/private/var
executing /bin/rm
creating directory (owner=0 mode=755) /mnt1/private/var
entering modify_fstab
entering clear_persistent_boot_args
executing /usr/sbin/nvram
entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)
IOConnectCallStructMethod(0) failed: 0xe00002e2
attempting to dump restore log
writing log file: /mnt1/restore.log
</string>
        <key>MsgType</key>
        <string>StatusMsg</string>
        <key>Status</key>
        <integer>37</integer>
</dict>
</plist>
Log is available:
 ARM Device=uart2 at 0x82700000(0xd2c26000)
AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart3 at 0x82800000(0xd2c35000)
AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart6 at 0x82b00000(0xd2c7d000)
[000000.372690]: AppleSamsungDPTXController::disableInterrupts: disabling
[000000.000042]: AppleSamsungDPTXController::disableInterrupts: _outstandingIO=0 _pendingDisable=0
HighlandParkAudioDevice::start: 0x82063000, highland-park mIICNub: 0x81e19e00, mIISNub: 0x8243fe80, mSerialNub: 0x82442200, sampleRate = 44100, ol=8, oi=7
AppleAP3GDL::probe found device with ID: 0xd3
AppleAP3GDL::handleStart _calibrationMatrix [63663 -29 -193] [669 61250 146] [64 -381 65310]
AppleAP3GDL::handleStart _calibrationInverseMatrix [67463 33 198] [-736 70121 -158] [-69 408 65762]
AppleBaseband: inconsistent mux function setup (0 0 0 0 0 0)
AppleNANDFTL started with IOFlashStoragePartition provider
AppleNANDFTL located at physical nand block offset 16
metadata-whitening was found and it's set to 1
default-ftl-version was found and it's set to 1
diag-bits is supplied by AppleNANDFTL
[FTL:MSG] Apple NAND Driver (AND) RW
[FTL:MSG] FIL_Init            [OK]
[FTL:MSG] BUF_Init            [OK]
[FTL:MSG] FPart Init          [OK]
AppleMultitouchN1SPI: successfully started
AppleMultitouchN1SPI: using DMA for bootloading
AppleMultitouchN1SPI: Logging is ENABLED
virtual bool AppleCLCD::start_hardware(IOService*), ditherCfg: 0x80000001 mIsDitherFor8Bits: 1
IOReturn AppleCLCD::set_ditherTable_state(bool), mIsDitherFor8Bits is true, no dynamic dither table.
IOSurface: buffer allocation size is zero
AppleM2ScalerCSCDriver: Added framebuffer device: AppleCLCD  id: c8124000
AppleRGBOUT: TVOUT device is detected
AppleD1815PMUPowerSource: AppleUSBCableDetect 1
AppleD1815PMUPowerSource: AppleUSBCableType USBHost
AppleEmbeddedUSBArbitrator::_usbCableTypeNotificationGated : cableType: USBHost
AppleEmbeddedUSBArbitrator::handleUSBCableTypeChange : Connected to a USB Host
AppleEmbeddedUSBNub::withProvider : allocated new nub 0x82827d00
AppleEmbeddedUSBNub::initWithProvider : finished nub init
AppleEmbeddedUSBArbitrator::_publishNubs : nub published
AppleSynopsysOTGDevice::init : Logging Buffer Length = 4K
AppleSynopsysOTGDevice::start : object is 0x825e9000, registers at 0xd3bc2000, 0x86100000 physical
AppleSynopsysOTGDevice::findMaxEndpoints: in EPs: 7, out EPs: 7, max_endpoint: 8, num_endpoints: 14 
AppleSynopsysOTGDevice::handleUSBCableConnect cable connected, but don't have device configuration yet
AppleSynopsysOTGDevice::start : start finished
AppleMultitouchN1SPI: detected HBPP. driver will be kept alive
IOSDIOController::enumerateSlot(): Searching for SDIO device in slot: 0
IOSDIOController::enumerateSlot(): Found SDIO I/O device. Function count(1), memory(0)
AppleEmbeddedUSBArbitrator::_usbCableTypeNotificationGated : cableType: USBHost
AppleS5L8930XUSBArbitrator::handleUSBCableTypeChange : no change in cable-type
IOSDIOIoCardDevice::parseFn0CIS(): Device manufacturer ID 0x2d0, Product ID 0x4329
IOSDIOIoCardDevice::parseFn0CIS(): Manufacturer: ""
IOSDIOIoCardDevice::parseFn0CIS(): Product:      ""
IOSDIOIoCardDevice::parseFn0CIS(): ProductInfo0: "s=B1"
IOSDIOIoCardDevice::parseFn0CIS(): ProductInfo1: "P=N90 m=3.1 V=u"
AppleBCMWLAN::init(): AppleBCMWLAN-42 May 26 2010 22:44:52
AppleBCMWLAN::init(): Starting with debug level: 4, debug flags: 00000000
AppleBCMWLAN::init(): AppleBCMWLAN-42 May 26 2010 22:44:52
AppleBCMWLAN::init(): Starting with debug level: 4, debug flags: 00000000
found suitable IOMobileFramebuffer: AppleCLCD
display-scale = 2
display-rotation = 0
found PTP interface
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49152
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49153
recv(11, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49154
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49155
recv(14, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49157
recv(17, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49158
recv(9, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49156
recv(9, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49161
recv(17, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49163
recv(20, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49159
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49160
Result new session 0x83f8ef80 established 62078<-lo0->49161 62078<-usb->55852
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078<-lo0->49162 62078<-usb->56108
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed80 established 62078<-lo0->49163 62078<-usb->56364
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078<-lo0->49164 62078<-usb->56620
AppleUSBDeviceMux::handleConnectResult new session 0x82570b80 established 62078<-lo0->49165 62078<-usb->56876
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed80
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570b00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed80 established 62078<-lo0->49166 62078<-usb->57132
AppleUSBDeviceMux::handleConnectResult new session 0x82570b00 established 62078<-lo0->49167 62078<-usb->57388
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570b80
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
AppleUSBDeviceMux::handleConnectResult new session 0x82570b80 established 62078<-lo0->49168 62078<-usb->57644
recv(13, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49165
recv(12, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49162
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49167
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49169
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49170
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49171
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49172
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49173
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49174
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49175
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49176
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49177
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49178
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49179
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49180
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49181
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49182
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49183
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49184
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49185
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49186
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49187
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49188
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49189
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49190
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49191
recv(8, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49192
 closing 0x82570a00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49190 62078<-usb->63276
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49191 62078<-usb->63532
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49192 62078<-usb->63788
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleBCMWLAN::handleIOKitBusyWatchdogTimeout(): Error, no successful firmware download after 60000 ms!! Giving up...
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49193 62078<-usb->64044
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49193
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49194 62078<-usb->64300
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49194
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49195 62078<-usb->64556
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49195
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49196
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49196 62078<-usb->64812
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49197 62078<-usb->65068
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49197
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49198 62078<-usb->65324
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49198
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49199 62078<-usb->45
recv(6, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49199
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49200
close(caller = 0x5695): remote port = 49202
recv(11, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49201
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49200 62078<-usb->301
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49201 62078<-usb->557
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49202 62078<-usb->813
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
recv(9, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49164
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
close(caller = 0x5695): remote port = 49203
close(caller = 0x5695): remote port = 49205
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49204
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49203 62078<-usb->1069
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078<-lo0->49204 62078<-usb->1325
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef00 established 62078<-lo0->49205 62078<-usb->1581
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
close(caller = 0x5695): remote port = 49206
close(caller = 0x5695): remote port = 49208
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49207
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef00 established 62078<-lo0->49206 62078<-usb->1837
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49207 62078<-usb->2093
AppleUSBDeviceMux::sessionUpcall socket is closed, session 0x83f8ef00 (62078<-lo0->49206 62078<-usb->1837)
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078<-lo0->49208 62078<-usb->2349
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49209
close(caller = 0x5695): remote port = 49211
close(caller = 0x5695): remote port = 49212
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49210
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078<-lo0->49209 62078<-usb->2605
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49210 62078<-usb->2861
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49211 62078<-usb->3117
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49212 62078<-usb->3373
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49213
close(caller = 0x5695): remote port = 49215
close(caller = 0x5695): remote port = 49216
close(caller = 0x5695): remote port = 49217
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49214
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49213 62078<-usb->3629
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49214 62078<-usb->3885
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed00 established 62078<-lo0->49215 62078<-usb->4141
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed00
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078<-lo0->49216 62078<-usb->4397
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078<-lo0->49217 62078<-usb->4653
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49218
close(caller = 0x5695): remote port = 49220
close(caller = 0x5695): remote port = 49221
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49219
AppleUSBDeviceMux::handleConnectResult new session 0x82570c00 established 62078<-lo0->49218 62078<-usb->4909
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49219 62078<-usb->5165
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570c00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed00 established 62078<-lo0->49220 62078<-usb->5421
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49221 62078<-usb->5677
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49222
close(caller = 0x5695): remote port = 49224
close(caller = 0x5695): remote port = 49225
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49223
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49222 62078<-usb->5933
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49223 62078<-usb->6189
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49224 62078<-usb->6445
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49225 62078<-usb->6701
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49226
close(caller = 0x5695): remote port = 49228
close(caller = 0x5695): remote port = 49229
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49227
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49226 62078<-usb->6957
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49227 62078<-usb->7213
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49228 62078<-usb->7469
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078<-lo0->49229 62078<-usb->7725
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49230
close(caller = 0x5695): remote port = 49232
close(caller = 0x5695): remote port = 49233
recv(10, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49231
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078<-lo0->49230 62078<-usb->7981
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49231 62078<-usb->8237
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
AppleUSBDeviceMux::handleConnectResult new session 0x82570a00 established 62078<-lo0->49232 62078<-usb->8493
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x82570a00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed00 established 62078<-lo0->49233 62078<-usb->8749
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed00
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f5c380
close(caller = 0x5695): remote port = 49234
close(caller = 0x5695): remote port = 49236
close(caller = 0x5695): remote port = 49237
close(caller = 0x5695): remote port = 49238
client protocol version 12
Restore options:
        SystemPartitionSize            => <CFNumber 0xb0bbd0 [0x1a9d5c]>{value = +1024, type = kCFNumberSInt64Type}
entering partition_nand_device
device supports boot-from-NAND
nand device is already partitioned
entering wait_for_storage_device
entering format_effaceable_storage
effaceable storage is formatted, clearing it
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ed00 established 62078<-lo0->49234 62078<-usb->9005
AppleUSBDeviceMux::handleConnectResult new session 0x83f5c380 established 62078<-lo0->49235 62078<-usb->9261
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ed00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49236 62078<-usb->9517
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078<-lo0->49237 62078<-usb->9773
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ef80
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 62078<-lo0->49238 62078<-usb->10029
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ef80 established 62078<-lo0->49239 62078<-usb->10285
void AppleUSBDeviceMux::handleConnectResult(BulkUSBMuxSession*, errno_t) new session to port 1082 failed: 61
effaceable storaged cleared
entering check_for_restore_log
could not find partition, unable to check for restore log
entering create_filesystem_partitions
NAND format complete
creating encrypted data partition
wipe entire partition: 1 (old = 0 new = 1024)
block size for /dev/disk0s1: 8192
/sbin/newfs_hfs -s -v System -b 8192 -n a=8192,c=8192,e=8192 /dev/disk0s1 
executing /sbin/newfs_hfs
Initialized /dev/rdisk0s1 as a 1024 MB HFS Plus volume
block size for /dev/disk0s2s1: 8192
/sbin/newfs_hfs -s -v Data -J -P -b 8192 -n a=8192,c=8192,e=8192 /dev/disk0s2s1 
executing /sbin/newfs_hfs
Initialized /dev/rdisk0s2s1 as a 14 GB HFS Plus volume with a 8192k journal
entering restore_images
executing /usr/sbin/asr
void AppleUSBDeviceMux::handleConnectResult(BulkUSBMuxSession*, errno_t) new session to port 12345 failed: 61
ASR STATUS: start       223     multicast-client
ASR: Waiting for connection attempt from server
ASR STATUS: setup
ASR: Validating target...
ASR: done
ASR STATUS: metadata
ASR: Validating source...
AppleUSBDeviceMux::handleConnectResult new session 0x83f8ee00 established 12345<-lo0->49242 12345<-usb->11053
ASR: Using Hardware AES
ASR: Using Hardware AES
ASR: Using Hardware AES
ASR: done
ASR: Using Hardware AES
ASR: Warning: You may not be able to start up a computer with the target volume.
ASR: Retrieving scan information...done
ASR: Validating sizes...
ASR: done
ASR STATUS: restore
ASR RESTORE PROGRESS: 2%
ASR RESTORE PROGRESS: 4%
ASR RESTORE PROGRESS: 6%
ASR RESTORE PROGRESS: 8%
ASR RESTORE PROGRESS: 10%
ASR RESTORE PROGRESS: 12%
ASR RESTORE PROGRESS: 14%
ASR RESTORE PROGRESS: 16%
ASR RESTORE PROGRESS: 18%
ASR RESTORE PROGRESS: 20%
ASR RESTORE PROGRESS: 22%
ASR RESTORE PROGRESS: 24%
ASR RESTORE PROGRESS: 26%
ASR RESTORE PROGRESS: 28%
ASR RESTORE PROGRESS: 30%
ASR RESTORE PROGRESS: 32%
ASR RESTORE PROGRESS: 34%
ASR RESTORE PROGRESS: 36%
ASR RESTORE PROGRESS: 38%
ASR RESTORE PROGRESS: 40%
ASR RESTORE PROGRESS: 42%
recv(18, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49243
recv(18, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49244
recv(18, 4) failed: connection closed
unable to read message size: -1
could not receive message
close(caller = 0x5695): remote port = 49245
ASR RESTORE PROGRESS: 44%
AppleUSBDeviceMux::handleConnectResult new session 0x84215800 established 62078<-lo0->49243 62078<-usb->11309
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x84215800
AppleUSBDeviceMux::handleConnectResult new session 0x84215780 established 62078<-lo0->49244 62078<-usb->11565
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x84215780
AppleUSBDeviceMux::handleConnectResult new session 0x84215800 established 62078<-lo0->49245 62078<-usb->11821
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x84215800
ASR RESTORE PROGRESS: 46%
ASR RESTORE PROGRESS: 48%
ASR RESTORE PROGRESS: 50%
ASR RESTORE PROGRESS: 52%
ASR RESTORE PROGRESS: 54%
ASR RESTORE PROGRESS: 56%
ASR RESTORE PROGRESS: 58%
ASR RESTORE PROGRESS: 60%
ASR RESTORE PROGRESS: 62%
ASR RESTORE PROGRESS: 64%
ASR RESTORE PROGRESS: 66%
ASR RESTORE PROGRESS: 68%
ASR RESTORE PROGRESS: 70%
ASR RESTORE PROGRESS: 72%
ASR RESTORE PROGRESS: 74%
ASR RESTORE PROGRESS: 76%
ASR RESTORE PROGRESS: 78%
ASR RESTORE PROGRESS: 80%
ASR RESTORE PROGRESS: 82%
ASR RESTORE PROGRESS: 84%
ASR RESTORE PROGRESS: 86%
ASR RESTORE PROGRESS: 88%
ASR RESTORE PROGRESS: 90%
ASR RESTORE PROGRESS: 92%
ASR RESTORE PROGRESS: 94%
ASR RESTORE PROGRESS: 96%
ASR RESTORE PROGRESS: 98%
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x83f8ee00
ASR RESTORE PROGRESS: 100%
ASR: Copied 995688960 bytes in 75.61 seconds, 12859.84 KiB/s
ASR STATUS: verify
ASR VERIFY PROGRESS: 2%
ASR VERIFY PROGRESS: 4%
ASR VERIFY PROGRESS: 6%
ASR VERIFY PROGRESS: 8%
ASR VERIFY PROGRESS: 10%
ASR VERIFY PROGRESS: 12%
ASR VERIFY PROGRESS: 14%
ASR VERIFY PROGRESS: 16%
ASR VERIFY PROGRESS: 18%
ASR VERIFY PROGRESS: 20%
ASR VERIFY PROGRESS: 22%
ASR VERIFY PROGRESS: 24%
ASR VERIFY PROGRESS: 26%
ASR VERIFY PROGRESS: 28%
ASR VERIFY PROGRESS: 30%
ASR VERIFY PROGRESS: 32%
ASR VERIFY PROGRESS: 34%
ASR VERIFY PROGRESS: 36%
ASR VERIFY PROGRESS: 38%
ASR VERIFY PROGRESS: 40%
ASR VERIFY PROGRESS: 42%
ASR VERIFY PROGRESS: 44%
ASR VERIFY PROGRESS: 46%
ASR VERIFY PROGRESS: 48%
ASR VERIFY PROGRESS: 50%
ASR VERIFY PROGRESS: 52%
ASR VERIFY PROGRESS: 54%
ASR VERIFY PROGRESS: 56%
ASR VERIFY PROGRESS: 58%
ASR VERIFY PROGRESS: 60%
ASR VERIFY PROGRESS: 62%
ASR VERIFY PROGRESS: 64%
ASR VERIFY PROGRESS: 66%
ASR VERIFY PROGRESS: 68%
ASR VERIFY PROGRESS: 70%
ASR VERIFY PROGRESS: 72%
ASR VERIFY PROGRESS: 74%
ASR VERIFY PROGRESS: 76%
ASR VERIFY PROGRESS: 78%
ASR VERIFY PROGRESS: 80%
ASR VERIFY PROGRESS: 82%
ASR VERIFY PROGRESS: 84%
ASR VERIFY PROGRESS: 86%
ASR VERIFY PROGRESS: 88%
ASR VERIFY PROGRESS: 90%
ASR VERIFY PROGRESS: 92%
ASR VERIFY PROGRESS: 94%
ASR VERIFY PROGRESS: 96%
ASR VERIFY PROGRESS: 98%
ASR VERIFY PROGRESS: 100%
ASR: Verified SHA-1 checksum 995688960 bytes in 25.93 seconds, 37504.02 KiB/s
ASR STATUS: finish
entering mount_filesystems
executing /sbin/fsck_hfs
** /dev/rdisk0s1
   Executing fsck_hfs (version diskdev_cmds-488.1.7~39).
** Checking non-journaled HFS Plus Volume.
** Detected a case-sensitive volume.
** Checking extents overflow file.
** Checking catalog file.
** Checking multi-linked files.
** Checking catalog hierarchy.
** Checking extended attributes file.
** Checking volume bitmap.
** Checking volume information.
** The volume Apex8A293.N90OS appears to be OK.
executing /sbin/mount
executing /sbin/fsck_hfs
disk0s2s1: ioctl(_IOW,'d',24,4) is unsupported.
** /dev/rdisk0s2s1
   Executing fsck_hfs (version diskdev_cmds-488.1.7~39).
** Checking Journaled HFS Plus volume.
** Detected a case-sensitive volume.
** Checking extents overflow file.
** Checking catalog file.
** Checking multi-linked files.
** Checking catalog hierarchy.
** Checking extended attributes file.
** Checking volume bitmap.
** Checking volume information.
** The volume Data appears to be OK.
executing /sbin/mount
entering install_kernel_cache
writing kernelcache to /mnt1/System/Library/Caches/com.apple.kernelcaches/kernelcache
entering install_secure_vault_daemon
entering get_hardware_platform
platform-name = s5l8930x
linking /mnt1/usr/sbin/securekeyvaultd to /mnt1/usr/sbin/securekeyvaultd.s5l8930x
no securekeyvaultd for s5l8930x
entering fixup_var
remove_path /mnt1/private/var
executing /bin/rm
creating directory (owner=0 mode=755) /mnt1/private/var
entering modify_fstab
entering clear_persistent_boot_args
executing /usr/sbin/nvram
entering update_NOR
entering img3_update_NOR
img3_flash_NOR_image: flashing LLB data (length = 0x13984)
IOConnectCallStructMethod(0) failed: 0xe00002e2
attempting to dump restore log
writing log file: /mnt1/restore.log

ERROR: Unable to successfully restore device
