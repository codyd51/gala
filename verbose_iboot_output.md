=======================================
::
:: iBEC for n90ap, Copyright 2010, Apple Inc.
::
::      BUILD_TAG: iBoot-889.24
::
::      BUILD_STYLE: RELEASE
::
::      USB_SERIAL_NUMBER: CPID:8930 CPRV:20 CPFM:03 SCEP:01 BDID:00 ECID:00000363F615C377 IBFL:00 SRNM:[84033X5RA4S]
::
=======================================

Entering recovery mode, starting command prompt
creating device tree at 0x43f00000 of size 0xe04c, from image at 0x41000000
creating ramdisk at 0x44000000 of size 0x1400000, from image at 0x41000000
Attempting to validate kernelcache @ 0x41000000
Loading kernel cache at 0x43000000
Uncompressed kernel cache at 0x43000000
gBootArgs.commandLine = [rd=md0 -v nand-enable-reformat=1 -progress debug=0x14e serial=3 ]
Installing WIFI Calibration
kernelcache prepped at address 0x40065050
iBoot version: iBoot-889.24
AppleS5L8930XIO::start: chip-revision: C0
AppleBaseband::start(0x825c7180): baseband
AppleARMBacklight::start: trying device-specific conversion table backlight-5
AppleARMBacklight::start: using brightness offset of 0
IOSurfaceRoot::installMemoryRegions()
AppleS5L8930XIO::start: PIO Errors Enabled
AppleARMPL192VIC::start: _vicBaseAddress = 0xd29fd000
AppleS5L8930XGPIOIC::start: gpioicBaseAddress: 0xc9874000
AppleS5L8930XPerformanceController::start: _pcBaseAddress: 0xd28f1000
AppleS5L8930XPerformanceController::start: pcVoltageStateCount: 2
Voltage State 0 : .vsPerformanceLimit: 2 .vsDeviceConstraint: 31ff7f4f 37f5f0ff f1f39077 f7ffffff
Voltage State 1 : .vsPerformanceLimit: 1 .vsDeviceConstraint: 31ff7f7f 37f5f0ff f1f3d077 f7ffffff
AppleS5L8930XPerformanceController::start: pcPerformanceStateCount: 4
Performance State 0 : .psPerformanceDivider: 1 .psVoltageRequired: 1 .psDeviceConstraint: 31ff7f7f 37f5f0ff f1f3d077 f7ffffff
Performance State 1 : .psPerformanceDivider: 2 .psVoltageRequired: 0 .psDeviceConstraint: 31ff5f4a 17f5f0ff f153d077 f7ffffff
Performance State 2 : .psPerformanceDivider: 5 .psVoltageRequired: 0 .psDeviceConstraint: 31ff4f48 07d5f0ff f153d077 f7ffffff
Performance State 3 : .psPerformanceDivider: 16 .psVoltageRequired: 0 .psDeviceConstraint: 31ff4f48 0615f0ff f153d077 f7ffffff
AppleS5L8930XPerformanceController: Dynamic Performance State Management Enabled with 2 voltage and 4 perfomance states
AppleS5L8930XPerformanceController: Dynamic Voltage Control Enabled with 10000us activity timeout and 100us grace period
AppleS5L8930XPerformanceController: Dynamic Voltage Dithering Enabled with 8000us period and 1000us threshold
IOSDIOController::init(): IOSDIOFamily-28 May 26 2010 22:31:41
AppleS5L8920XIOPSDIO::start(): AppleS5L8920X-241.9 May 29 2010 22:15:56
AppleS5L8900XSPIController::start: spi0: _spiBaseAddress = 0xcf8a5000, _spiVersion = 1 _spiInternalCS = 0
AppleS5L8900XSPIController::start: spi1: _spiBaseAddress = 0xcf8a6000, _spiVersion = 1 _spiInternalCS = 0
AppleS5L8920XI2CController::start: i2c0 _i2cBaseAddress: 0xcf8ae000
AppleS5L8920XI2CController::start: i2c2 _i2cBaseAddress: 0xd1f5d000
AppleS5L8900XI2SController::start: i2s0 i2sBaseAddress: 0xd1f5e400 i2sVersion: 2
AppleS5L8900XI2SController::start: i2s1 i2sBaseAddress: 0xd1f65400 i2sVersion: 2
AppleS5L8900XI2SController::start: i2s2 i2sBaseAddress: 0xd1f66400 i2sVersion: 2
AppleS5L8920XPWM::start: _pwmBaseAddress: 0xd1f6d000
AppleUSBPhy::start : finished
AppleS5L8930XUSBPhy::start : registers at virtual: 0xd1f6e000, physical: 0x86000000
AppleS5L8930XUSBPhy::start : _phyTuningVal: 00000733
AppleS5L8930XUSBPhy::start : finished
AppleVXD375 - start (provider 0x82685100)
AppleVXD375 - compiled on May 31 2010 19:43:36
+ H264EncDriver: start (provider 0x826cfc00)
+ H264EncDriver: compiled on May 31 2010 19:43:27
  AppleJPEGDriver::start: mapped IO register at 0x88200000/0xd1f7d000
  AppleH3CamIn::start
+ AppleM2ScalerCSCDriver[0x827dcf00]::start(provider 0x826cfa00)
  AppleS5L8900XMIPIDSIController::start: _dsimBaseAddress = 0xd1f85000
  AppleS5L8720XSWI::start: _swiBaseAddress: 0xd1f86000
  AppleRGBOUT Initializing
  [000049.44788590]: AppleSamsungDPTXController::handleStart: couldn't find AppleARMFunction for "function-mux_shutdown"
  [000000.010549]: AppleSamsungDPTXController::handleStart: couldn't find AppleARMFunction for "function-mux_select"
  [000000.010310]: AppleSamsungDPTXController::handleStart: registers at 0xd1f8d000, 0x84900000 physical
  AppleBaseband: Could not find mux function
  AppleS5L8930XUSBArbitrator::handleStart : USB_CTL register at virtual: 0xd1f9d000, physical: 0xbf108000
  AppleEmbeddedUSBArbitrator::start : finished
  AppleS5L8930XUSBArbitrator::setPowerStateGated : powerstate = 1
  AppleEmbeddedUSBArbitrator::setPowerStateGated : powerstate = 1
  AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart0 at 0x82500000(0xd1f9e000)
  AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart4 at 0x82900000(0xd1fa6000)
  AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart5 at 0x82a00000(0xd1fad000)
  HighlandParkAudioDevice::Start
  AppleS5L8920XARM7M::start: mapped I/O registers at 0xd1fae000/0x86300000, 0xd1fb5000/0xbf300000
  AppleS5L8920XARM7M::_prepareFirmwareImage: EmbeddedIOP firmware s5l8930x-RELEASE iBoot-889.24
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 0
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 4032
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 8096
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 11168
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 15136
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 19200
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 23248
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 27296
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 31360
  AppleVXD375: deviceType = H3P
  AppleS5L8720XSWI::start: _swiBaseAddress: _swiWorstCaseIntraVBUCK=77
  AppleD1815PMU::start: pmu _pmuIICNub: 0x82853680 built 22:31:37 May 26 2010
  AppleLIS331DLH::handleStart _calibrationMatrix [64278 -1818 -535] [-1203 61227 513] [460 15 64048]
  AppleLIS331DLH::handleStart _calibrationOffsets [546759 186709 752168]
  AppleH3CamIn::start - DART dead-mappings start=0x00000000, end=0x01000000
  H264Driver: power_off_hardware
  H264Driver: power_on_hardware
  H264Driver: power_off_hardware
  AppleCLCD, fMapper: 0x829e8400
+ AppleCLCD(0xc7f74000)::start_hardware
  virtual bool AppleCLCD::start_hardware(IOService*) - Registers->virtual = 0xd295d000
  DisplayPipe fRegisters virtual = 0xd2f52000  
  AppleRGBOUT, fMapper: 0x829e8000
  virtual bool AppleRGBOUT::start_hardware(IOService*) - Registers->virtual = 0xd2965000
  DisplayPipe fRegisters virtual = 0xd2f59000  
  void AppleRGBOUT::verify_swap_gated(IOMFBSwapIORequest*, bool*) failed mIsDPOut: 0 mDPDriver: 0 fTVOUTDelegate: 0
  AppleRGBOUT verify_swap failed
  void AppleRGBOUT::verify_swap_gated(IOMFBSwapIORequest*, bool*) failed mIsDPOut: 0 mDPDriver: 0 fTVOUTDelegate: 0
  AppleRGBOUT verify_swap failed
  Scaler enableDeviceClock(true,FULL_CLOCK_INDEX) = 0x0
  Scaler HW version at start is 0x20007
  Scaler enableDeviceClock(false,FULL_CLOCK_INDEX) = 0x0
  AppleM2ScalerCSCDriver: Added framebuffer device: AppleRGBOUT  id: c0a1a000
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 35296
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 38368
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 42456
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 42456
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 42456
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 42456
  SDHC: Ping received, IOKit <--> IOP Connection established
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 46544
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 46544
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 46544
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 46544
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 50128
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 52176
  AppleS5L8920XARM7M::arm7mAllocateVisibleMemory: visible memory allocation waste 52176
  AppleS5L8920XIOPFMI::start: ****** AppleS5L8920XIOPFMI started: 0x82698400
  configuring FMI0
  [NAND] h2fmi_iop_set_config:135 cmd->read_sample_cycles : 0
  [NAND] h2fmi_iop_set_config:136 cmd->read_setup_cycles  : 5
  [NAND] h2fmi_iop_set_config:137 cmd->read_hold_cycles   : 5
  [NAND] h2fmi_iop_set_config:138 cmd->write_setup_cyclesAppleAP3GDL::probe found device with ID: 0xd3
  AppleAP3GDL::handleStart _calibrationMatrix [63663 -29 -193] [669 61250 146] [64 -381 65310]
  AppleAP3GDL::handleStart _calibrationInverseMatrix [67463 33 198] [-736 70121 -158] [-69 408 65762]
  configuring FMI1
  [NAND] h2fmi_iop_set_config:135 cmd->read_sample_cycles : 0
  [NAND] h2fmi_iop_set_config:136 cmd->read_setup_cycles  : 5
  [NAND] h2fmi_iop_set_config:137 cmd->read_hold_cycles   : 5
  [NAND] h2fmi_iop_set_config:138 cmd->write_setup_cyclesIOFixed - Coeffs -[r,g,b] = [1003, 1142, 1123], [gain=3483]
  AppleMPU3100::probe -- Not the right part
  AppleEmbeddedI2CGyro::free .. why is someone calling free on me
  AppleD1815PMU::start: reading DOWN converter voltages
  AppleD1815PMU::start: DOWN0: 1100mV
  AppleD1815PMU::start: DOWN1: 1150mV
  AppleD1815PMU::start: DOWN2: 1200mV
  AppleD1815PMU::start: DOWN3: 725mV
  AppleD1815PMU::start: set VBUCK1_PRE1 to 950
  AppleS5L8920XIOPFMI: Found Chip ID 0x32944845 on FMI0:CE0
  AppleS5L8920XIOPFMI: Found Chip ID 0x32944845 on FMI0:CE1
  AppleS5L8920XIOPFMI: Found Chip ID 0x32944845 on FMI1:CE8
  AppleS5L8920XIOPFMI: Found Chip ID 0x32944845 on FMI1:CE9
  IOFlashStorageDevice::initWithRegistryEntry: starting
  AppleD1815PMU::start: set VBUCK1_PRE2 to 1100
  configuring FMI0
  [NAND] h2fmi_iop_set_config:135 cmd->read_sample_cycles : 1
  [NAND] h2fmi_iop_set_config:136 cmd->read_setup_cycles  : 1
  [NAND] h2fmi_iop_set_config:137 cmd->read_hold_cycles   : 1
  [NAND] h2fmi_iop_set_config:138 cmd->write_setup_cyclesAppleD1815PMU::start: using SWI for CPU BUCK changes
  configuring FMI1
  [NAND] h2fmi_iop_set_config:135 cmd->read_sample_cycles : 1
  [NAND] h2fmi_iop_set_config:136 cmd->read_setup_cycles  : 1
  [NAND] h2fmi_iop_set_config:137 cmd->read_hold_cycles   : 1
  [NAND] h2fmi_iop_set_config:138 cmd->write_setup_cyclesconfiguring FMI0
  [NAND] h2fmi_iop_set_config:135 cmd->read_sample_cycles : 1
  [NAND] h2fmi_iop_set_config:136 cmd->read_setup_cycles  : 1
  [NAND] h2fmi_iop_set_config:137 cmd->read_hold_cycles   : 1
  [NAND] h2fmi_iop_set_config:138 cmd->write_setup_cyclesAppleARMWatchDogTimer installing handlePEHaltRestart handler
  configuring FMI1
  [NAND] h2fmi_iop_set_config:135 cmd->read_sample_cycles : 1
  [NAND] h2fmi_iop_set_config:136 cmd->read_setup_cycles  : 1
  [NAND] h2fmi_iop_set_config:137 cmd->read_hold_cycles   : 1
  [NAND] h2fmi_iop_set_config:138 cmd->write_setup_cyclesIOFlashPartitionScheme::probe: probing with score 4
  AppleNANDFTL::probe: probing with score 3
  IOFlashStorageDevice::handleOpen: device being opened by 0x82aba780
  IOFlashPartitionScheme::readPartitionTable: reading partition tables from boot blocks
  IOFlashPartitionScheme::createPartitionDevices: found 8 partitions
  IOFlashPartitionScheme::loadPartitionTable: successfully read partition scheme
  IOFlashNVRAM::start: starting nand-backed NVRAM controller driver
  AppleNANDFTL::probe: probing with score 0
  AppleNANDFTL::start: Starting flash translation layer...
  AppleNANDFTL started with IOFlashStoragePartition provider
  AppleNANDFTL located at physical nand block offset 16
  AppleNANDFTL::_FILInit: driver advertises ReadMultiple
  AppleNANDFTL::_FILInit: driver advertises ReadScattered
  AppleNANDFTL::_FILInit: driver advertises bootloader pages
  AppleNANDFTL::_FILInit: driver advertises WriteMultiple
  AppleNANDFTL::_FILInit: driver advertises WriteScattered
  AppleNANDFTL::_FILInit: driver advertises WhiteningData
  AppleNANDFTL::_FILInit: driver advertises WhiteningMetadata
  metadata-whitening was found and it's set to 1
  default-ftl-version was found and it's set to 1
  diag-bits is supplied by AppleNANDFTL
  [FTL:MSG] Apple NAND Driver (AND) RW
  [FTL:MSG] FIL_Init            [OK]
  [FTL:MSG] BUF_Init            [OK]
  [FTL:MSG] FPart Init          [OK]
  BSD root: md0, major 2, minor 0
  com.apple.AppleFSCompressionTypeZlib kmod start
  virtual bool AppleMobileFileIntegrity::start(IOService*): built Jun  1 2010 18:13:35
  L2TP domain init
  L2TP domain init complete
  PPTP domain init
  com.apple.AppleFSCompressionTypeZlib load succeeded
  CDMA::_mapKeyID: key 1000/1 not enabled
  AppleS5L8920XBasebandSPIController::loadConfiguration: NCLK Frequency 48857142, Prescaler 3
  BasebandSPIDevice::exitLowPower: Invalid state inactive
  AppleSerialMultiplexer: adap::start: Frame size is 2048, Rx Buffer count is 16
  AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart1 at 0x82600000(0xd29e6000)
  AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart2 at 0x82700000(0xd29ee000)
  AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart3 at 0x82800000(0xd2a3d000)
  AppleS5L8900XSerial: Identified Serial Port on ARM Device=uart6 at 0x82b00000(0xd2a7d000)
  [000001.1154931]: AppleSamsungDPTXController::disableInterrupts: disabling
  [000000.006743]: AppleSamsungDPTXController::disableInterrupts: _outstandingIO=0 _pendingDisable=0
  AppleSerialMultiplexer: mux::start: created new mux (18) for spi-baseband with adapter BasebandSPIDevice
  AppleSerialMultiplexer: debugparams::init: Parsed flags "" ( 0 )
  AppleCS42L61Audio::start: 0x82855500, audio0 _wmIICNub: 0x82853480, _wmIISNub: 0x82ba0800
  HighlandParkAudioDevice::start: 0x82745000, highland-park mIICNub: 0x824fee00, mIISNub: 0x82b9a300, mSerialNub: 0x82b73800, sampleRate = 44100, ol=8, oi=7
  AppleBaseband: inconsistent mux function setup (0 0 0 0 0 0)
  AppleSerialMultiplexer: !! mux::setPowerStateGated: Skipping power state change
  AppleH3CamIn::start, fSensorExtClkFunction = 0x82A47DA0
  AppleH3CamIn::start, fSensorShutdownFunction = 0x82A47D80
  AppleH3CamIn::start, fSensorShutdownFunction2 = 0x82A47D60
  AppleH3CamIn::start, fSensorPowerFunction = 0x82A47D40
  AppleH3CamIn::start, fISPResetFunction = 0x82C77300
  AppleH3CamIn: fISPCPUFWBuffer, DART-mapped address: 0x01000000
  AppleH3CamIn: Shared memory metadata region mapped at DART translated address: 0x01041000
  AppleH3CamIn: CPU time-base registers mapped at DART translated address: 0x01045000
  AppleH3CamIn::power_off_hardware
  AppleH3CamIn::setPowerStateGated: 1
  AppleH3CamIn::setPowerStateGated, ISPCPU firmware not yet loaded
  AppleH3CamIn::setPowerStateGated: 0
  AppleMultitouchN1SPI: successfully started
  AppleMultitouchN1SPI: using DMA for bootloading
  AppleMultitouchN1SPI: Logging is ENABLED
  ApplePinotLCD: _lcdPanelID: 0xa19705c8
  virtual bool AppleCLCD::start_hardware(IOService*), ditherCfg: 0x80000001 mIsDitherFor8Bits: 1
  IOReturn AppleCLCD::set_ditherTable_state(bool), mIsDitherFor8Bits is true, no dynamic dither table.
  IOSurface: buffer allocation size is zero
  AppleM2ScalerCSCDriver: Added framebuffer device: AppleCLCD  id: c7f74000
  HighlandParkAudioDevice: ATSc values = 0x8 0x15 0x0 0x0
  AppleRGBOUT: TVOUT device is detected
  IOAccessoryPortSerial::start: iap: could not set up serial port: device is offline
  IOSDIOController::enumerateSlot(): Searching for SDIO device in slot: 0
  IOSDIOController::enumerateSlot(): Found SDIO I/O device. Function count(1), memory(0)
  AppleD1815PMUPowerSource: AppleUSBCableDetect 1
  AppleD1815PMUPowerSource: AppleUSBCableType USBHost
  AppleEmbeddedUSBArbitrator::_usbCableTypeNotificationGated : cableType: USBHost
  AppleEmbeddedUSBArbitrator::handleUSBCableTypeChange : Connected to a USB Host
  AppleEmbeddedUSBNub::withProvider : allocated new nub 0x82ebee80
  AppleEmbeddedUSBNub::initWithProvider : finished nub init
  AppleEmbeddedUSBArbitrator::_publishNubs : nub published
  AppleSynopsysOTGDevice::init : Logging Buffer Length = 4K
  AppleSynopsysOTGDevice::start : registers at 0xd397e000, 0x86100000 physical
  AppleSynopsysOTGDevice::start : object is 0x82c7e800, registers at 0xd397e000, 0x86100000 physical
  AppleSynopsysOTGDevice::findMaxEndpoints: in EPs: 7, out EPs: 7, max_endpoint: 8, num_endpoints: 14
  AppleSynopsysOTGDevice::handleUSBCableConnect cable connected, but don't have device configuration yet
  AppleSynopsysOTGDevice::start : start finished
  AppleMultitouchN1SPI: detected HBPP. driver will be kept alive
  com.apple.launchd 1     com.apple.launchd 1     *** launchd[1] has started up. ***
  com.apple.launchd 1     com.apple.launchd 1     *** Verbose boot, will log to /dev/console. ***
  IOSDIOIoCardDevice::parseFn0CIS(): Device manufacturer ID 0x2d0, Product ID 0x4329
  IOSDIOIoCardDevice::parseFn0CIS(): Manufacturer: ""
  IOSDIOIoCardDevice::parseFn0CIS(): Product:      ""
  IOSDIOIoCardDevice::parseFn0CIS(): ProductInfo0: "s=B1"
  IOSDIOIoCardDevice::parseFn0CIS(): ProductInfo1: "P=N90 m=3.1 V=u"
  AppleBCMWLAN::init(): AppleBCMWLAN-42 May 26 2010 22:44:52
  AppleBCMWLAN::init(): Starting with debug level: 4, debug flags: 00000000
  AppleBCMWLAN::init(): AppleBCMWLAN-42 May 26 2010 22:44:52
  AppleBCMWLAN::init(): Starting with debug level: 4, debug flags: 00000000
  AppleEffaceableNAND::start():[INIT] started
  Bug: launchctl.c:3599 (24106):17: ioctl(s6, SIOCAIFADDR_IN6, &ifra6) != -1
  IOFlashNVRAM::start: nand nvram started successfully
  AppleEmbeddedUSBArbitrator::_usbCableTypeNotificationGated : cableType: USBHost
  AppleS5L8930XUSBArbitrator::handleUSBCableTypeChange : no change in cable-type
  entering set_boot_stage
  found suitable IOMobileFramebuffer: AppleCLCD
  display-scale = 2
  display-rotation = 0
  CFPreferences: user home directory at file://localhost/var/root/ is unavailable. User domains will be volatile.
  found PTP interface
  AppleSynopsysOTGDevice - Configuration: PTP
  AppleSynopsysOTGDevice          Interface: PTP
  AppleSynopsysOTGDevice - Configuration: iPod USB Interface
  AppleSynopsysOTGDevice          Interface: USBAudioControl
  AppleSynopsysOTGDevice          Interface: USBAudioStreaming
  AppleSynopsysOTGDevice          Interface: IapOverUsbHid
  AppleSynopsysOTGDevice - Configuration: PTP + Apple Mobile Device
  AppleSynopsysOTGDevice          Interface: PTP
  AppleSynopsysOTGDevice          Interface: AppleUSBMux
  AppleSynopsysOTGDevice - Configuration: PTP + Apple Mobile Device + Apple USB Ethernet
  AppleSynopsysOTGDevice          Interface: PTP
  AppleSynopsysOTGDevice          Interface: AppleUSBMux
  AppleSynopsysOTGDevice          Interface: AppleUSBEthernet
  AppleSynopsysOTGDevice::gated_registerFunction Register function USBAudioStreaming
  IOAccessoryPortUSB::start
  virtual bool AppleUSBDeviceMux::start(IOService*) build: May 26 2010 22:42:28
  AppleSynopsysOTGDevice::gated_registerFunction Register function IapOverUsbHid
  AppleSynopsysOTGDevice::gated_registerFunction Register function AppleUSBEthernet
  AppleUSBEthernetDevice::start: Device MAC address = 0a:0b:ad:0b:ab:e0
  AppleUSBEthernetDevice::start: Host MAC address = 7c:c5:37:b9:db:4d
  init_waste
  AppleSynopsysOTGDevice::gated_registerFunction Register function AppleUSBMux
  AppleSynopsysOTGDevice::gated_registerFunction Register function USBAudioControl
  AppleSynopsysOTGDevice::gated_registerFunction Register function PTP
  AppleSynopsysOTGDevice::gated_registerFunction all functions registered- we are ready to start usb stack
  AppleS5L8930XUSBPhy::powerUp : with_hsic: 0
  AppleEmbeddedUSBArbitrator::enableDeviceClock : enable: 1, index: 0
  AppleS5L8930XUSBPhy::enableDeviceMode : enable: 1
  read new style signature 0x43313131 (line:405)
  [FTL:MSG] VSVFL Register  [OK]
  [WMR:MSG] Metadata whitening is set in NAND signature
  [FTL:MSG] VFL Init            [OK]
  virtual IOReturn AppleUSBDeviceMux::setProperties(OSObject*) setting debug level to 7
  AppleImage3NORAccess::start imageVersion: 3
  AppleS5L8920XIOPFMI: Info: _fmiBankCount = 2 x 4 = 8, type=1376273, diesPerCS: 1, this = 0x82698400
  AppleS5L8920XIOPFMI: Info: _fmiBankCount = 2 x 4 = 8, type=1376273, diesPerCS: 1, this = 0x82698400
  [FTL:MSG] VFL_Open            [OK]
  [FTL:MSG] YAFTL Register  [OK]
  [FTL:MSG] FTL_Open            [OK]
  AppleNANDFTL::start: block device created, ready for work
  AppleNANDFactoryBBT::start: ready
  AppleSynopsysOTGDevice::handleUSBReset
  AppleSynopsysOTGDevice::stallBadSetupRequest request: 80 06 0f00 0000 0005
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9680 established 62078<-lo0->49152 62078<-usb->40240
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9680
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9d80 established 62078<-lo0->49153 62078<-usb->40496
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9680 established 62078<-lo0->49154 62078<-usb->40752
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9800 established 62078<-lo0->49155 62078<-usb->41008
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9480 established 62078<-lo0->49156 62078<-usb->41264
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9780 established 62078<-lo0->49157 62078<-usb->41520
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9700 established 62078<-lo0->49158 62078<-usb->41776
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9500 established 62078<-lo0->49159 62078<-usb->42032
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9400 established 62078<-lo0->49160 62078<-usb->42288
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9600 established 62078<-lo0->49161 62078<-usb->42544
  recv(8, 4) failed: connection closed
  unable to read message size: -1
  could not receive message
  close(caller = 0x5695): remote port = 49152
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9d80
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9680
  AppleSynopsysOTGDevice::stallBadSetupRequest request: 80 06 0f00 0000 0005
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9800
  AppleSynopsysOTGDevice::stallBadSetupRequest request: 80 06 0f00 0000 0005
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9480
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9780
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9500
  AppleSynopsysOTGDevice::stallBadSetupRequest request: 80 06 0f00 0000 0005
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9700
  AppleSynopsysOTGDevice::stallBadSetupRequest request: 80 06 0f00 0000 0005
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9480 established 62078<-lo0->49162 62078<-usb->42800
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9500 established 62078<-lo0->49163 62078<-usb->43056
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9700 established 62078<-lo0->49164 62078<-usb->43312
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9780 established 62078<-lo0->49165 62078<-usb->43568
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9680 established 62078<-lo0->49166 62078<-usb->43824
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9d80 established 62078<-lo0->49167 62078<-usb->44080
  recv(11, 4) failed: connection closed
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9400
  recv(14, 4) failed: connection closed
  recv(20, 4) failed: connection closed
  recv(29, 4) failed: connection closed
  recv(26, 4) failed: connection closed
  recv(23, 4) failed: connection closed
  recv(17, 4) failed: connection closed
  unable to read message size: -1
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9600
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9480
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9600 established 62078<-lo0->49168 62078<-usb->44336
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9500
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9800 established 62078<-lo0->49169 62078<-usb->44592
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9500 established 62078<-lo0->49170 62078<-usb->44848
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9280 established 62078<-lo0->49171 62078<-usb->45104
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9480 established 62078<-lo0->49172 62078<-usb->45360
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9600
  unable to read message size: -1
  unable to read message size: -1
  unable to read message size: -1
  unable to read message size: -1
  recv(32, 4) failed: connection closed
  unable to read message size: -1
  unable to read message size: -1
  could not receive message
  recv(8, 4) failed: connection closed
  recv(9, 4) failed: connection closed
  recv(38, 4) failed: connection closed
  recv(53, 4) failed: connection closed
  could not receive message
  could not receive message
  could not receive message
  unable to read message size: -1
  could not receive message
  could not receive message
  close(caller = 0x5695): remote port = 49154
  could not receive message
  unable to read message size: -1
  unable to read message size: -1
  unable to read message size: -1
  close(caller = 0x5695): remote port = 49159
  close(caller = 0x5695): remote port = 49158
  close(caller = 0x5695): remote port = 49153
  could not receive message
  close(caller = 0x5695): remote port = 49155
  close(caller = 0x5695): remote port = 49156
  unable to read message size: -1
  close(caller = 0x5695): remote port = 49157
  could not receive message
  could not receive message
  close(caller = 0x5695): remote port = 49160
  could not receive message
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9800
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9700
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9800 established 62078<-lo0->49173 62078<-usb->45616
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9500
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9780
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9500 established 62078<-lo0->49174 62078<-usb->45872
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9280
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9680
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9480
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9d80
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9480 established 62078<-lo0->49175 62078<-usb->46128
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9d80 established 62078<-lo0->49176 62078<-usb->46384
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9680 established 62078<-lo0->49177 62078<-usb->46640
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9180 established 62078<-lo0->49178 62078<-usb->46896
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9000 established 62078<-lo0->49179 62078<-usb->47152
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9680
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9280 established 62078<-lo0->49180 62078<-usb->47408
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9180
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9680 established 62078<-lo0->49181 62078<-usb->47664
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9000
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9180 established 62078<-lo0->49182 62078<-usb->47920
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9280
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9780 established 62078<-lo0->49183 62078<-usb->48176
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9680
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9680 established 62078<-lo0->49184 62078<-usb->48432
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9180
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9280 established 62078<-lo0->49185 62078<-usb->48688
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9780
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9000 established 62078<-lo0->49186 62078<-usb->48944
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9680
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9780 established 62078<-lo0->49187 62078<-usb->49200
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9280
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9680 established 62078<-lo0->49188 62078<-usb->49456
  void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9000
  AppleUSBDeviceMux::handleConnectResult new session 0x846d9280 established 62078<-lo0->49189 62078<-usb->49712

AppleUSBDeviceMux::handleConnectResult new session 0x846d9000 established 62078<-lo0->49190 62078<-usb->49968
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9780
AppleUSBDeviceMux::handleConnectResult new session 0x846d9180 established 62078<-lo0->49191 62078<-usb->50224
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9680
AppleUSBDeviceMux::handleConnectResult new session 0x846d9780 established 62078<-lo0->49192 62078<-usb->50480
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9280
AppleUSBDeviceMux::handleConnectResult new session 0x846d9580 established 62078<-lo0->49193 62078<-usb->50736
close(caller = 0x5695): remote port = 49168
close(caller = 0x5695): remote port = 49161
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9000
AppleUSBDeviceMux::handleConnectResult new session 0x846d9000 established 62078<-lo0->49194 62078<-usb->50992
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9180
AppleUSBDeviceMux::handleConnectResult new session 0x846d9600 established 62078<-lo0->49195 62078<-usb->51248
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9580
AppleUSBDeviceMux::handleConnectResult new session 0x846d9180 established 62078<-lo0->49196 62078<-usb->51504
close(caller = 0x5695): remote port = 49162
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9000
AppleUSBDeviceMux::handleConnectResult new session 0x846d9580 established 62078<-lo0->49197 62078<-usb->51760
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9600
AppleUSBDeviceMux::handleConnectResult new session 0x846d9700 established 62078<-lo0->49198 62078<-usb->52016
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9180
AppleUSBDeviceMux::handleConnectResult new session 0x846d9180 established 62078<-lo0->49199 62078<-usb->52272
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9580
AppleUSBDeviceMux::handleConnectResult new session 0x846d9600 established 62078<-lo0->49200 62078<-usb->52528
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9700
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9180
recv(14, 4) failed: connection closed
recv(56, 4) failed: connection closed
recv(41, 4) failed: connection closed
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9600
AppleUSBDeviceMux::handleConnectResult new session 0x846d9180 established 62078<-lo0->49201 62078<-usb->52784
AppleUSBDeviceMux::handleConnectResult new session 0x846d9600 established 62078<-lo0->49202 62078<-usb->53040
recv(44, 4) failed: connection closed
recv(12, 4) failed: connection closed
recv(47, 4) failed: connection void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9180
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9600
AppleUSBDeviceMux::handleConnectResult new session 0x846d9700 established 62078<-lo0->49203 62078<-usb->53296
AppleUSBDeviceMux::handleConnectResult new session 0x846d9280 established 62078<-lo0->49204 62078<-usb->53552
closed
recv(19, 4) failed: connection closed
recv(50, 4) failed: connection closed
recv(34, 4) failed: connection closed
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9780
AppleUSBDeviceMux::handleConnectResult new session 0x846d9580 established 62078<-lo0->49205 62078<-usb->53808
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9700
AppleUSBDeviceMux::handleConnectResult new session 0x846d9780 established 62078<-lo0->49206 62078<-usb->54064
revoid AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9280
AppleUSBDeviceMux::handleConnectResult new session 0x846d9700 established 62078<-lo0->49207 62078<-usb->54320
cv(59, 4) failed: connection closed
recv(62, 4) failed: connection closed
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9580
AppleUSBDeviceMux::handleConnectResult new session 0x846d9280 established 62078<-lo0->49208 62078<-usb->54576
recv(74, 4) failvoid AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9780
void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9700
ed: connection closed
recv(68, 4) failed: connection closed
recv(7void AppleUSBDeviceMux::handleMuxTCPInput(__mbuf*) received reset, closing 0x846d9280
1, 4) failed: connection closed
recv(77, 4) failed: connection closed
recv(80, 4) failed: connection closed
recv(83, 4) failed: connection closed
close(caller = 0x5695): remote port = 49163
recv(89, 4) failed: connection closed
recv(92, 4) failed: connection closed
recv(86, 4) failed: connection closed
recv(101, 4) failed: connection closed
recv(53, 4) failed: connection closed
recv(54, 4) failed: connection closed
recv(8, 4) failed: connection closed
recv(35, 4) failed: connection closed
recv(104, 4) failed: connection closed
recv(113, 4) failed: connection closed
recv(65, 4) failed: connection closed
unable to read message size: -1
unable to read message size: -1
recv(116, 4) failed: connection closed
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
recv(119, 4) failed: connection closed
recv(122, 4) failed: connection closed
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
recv(98, 4) failed: connection closed
unable to read message size: -1
unable to read message size: -1
recv(6, 4) failed: connection closed
recv(127, 4) failed: connection closed
unable to read message size: -1
unable to read message size: -1
recv(130, 4) failed: connection closed
recv(133, 4) failed: connection closed
recv(136, 4) failed: connection closed
unable to read message size: -1
unable to read message size: -1
recv(110, 4) failed: connection closed
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
recv(107, 4) failed: connection closed
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
could not receive message
unable to read message size: -1
unable to read message size: -1
could not receive message
could not receive message
could not receive message
unable to read message size: -1
could not receive message
unable to read message size: -1
could not receive message
could not receive message
could not receive message
recv(139, 4) failed: connection closed
could not receive message
could not receive message
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
could not receive message
could not receive message
unable to read message size: -1
unable to read message size: -1
unable to read message size: -1
could not receive message
could not receive message
unable to read message size: -1
could not receive message
could not receive message
could not receive message
could not receive message
could not receive message
unable to read message size: -1
could not receive message
could not receive message
could not receive message
could not receive message
could not receive message
could not receive message
could not receive message
could not receive message
close(caller = 0x5695): remote port = 49169
could not receive message
could not receive message
close(caller = 0x5695): remote port = 49165
close(caller = 0x5695): remote port = 49171
close(caller = 0x5695): remote port = 49166
could not receive message
close(caller = 0x5695): remote port = 49164
could not receive message
close(caller = 0x5695): remote port = 49167
close(caller = 0x5695): remote port = 49177
close(caller = 0x5695): remote port = 49172
unable to read message size: -1
close(caller = 0x5695): remote port = 49170
close(caller = 0x5695): remote port = 49178
could not receive message
could not receive message
could not receive message
close(caller = 0x5695): remote port = 49179
close(caller = 0x5695): remote port = 49183
could not receive message
could not receive message
could not receive message
close(caller = 0x5695): remote port = 49181
close(caller = 0x5695): remote port = 49182
could not receive message
close(caller = 0x5695): remote port = 49184
close(caller = 0x5695): remote port = 49185
close(caller = 0x5695): remote port = 49186
close(caller = 0x5695): remote port = 49188
close(caller = 0x5695): remote port = 49189
could not receive message
close(caller = 0x5695): remote port = 49193
close(caller = 0x5695): remote port = 49190
close(caller = 0x5695): remote port = 49191
close(caller = 0x5695): remote port = 49194
close(caller = 0x5695): remote port = 49195
close(caller = 0x5695): remote port = 49196
close(caller = 0x5695): remote port = 49199
close(caller = 0x5695): remote port = 49180
close(caller = 0x5695): remote port = 49187
close(caller = 0x5695): remote port = 49200
close(caller = 0x5695): remote port = 49201
close(caller = 0x5695): remote port = 49202
could not receive message
close(caller = 0x5695): remote port = 49203
close(caller = 0x5695): remote port = 49204
close(caller = 0x5695): remote port = 49192
close(caller = 0x5695): remote port = 49205
close(caller = 0x5695): remote port = 49206
close(caller = 0x5695): remote port = 49207
close(caller = 0x5695): remote port = 49198
close(caller = 0x5695): remote port = 49197
close(caller = 0x5695): remote port = 49208