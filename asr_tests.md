# After call to bl gather_image_metadata?
# Success branches away if r1 == 0
# But r1 == 1
#  cbz r1, loc_4736

Validating source...Using Hardware AES
*** ASR Reg-dump @ 0x0000470d
0x00000050
0x00000001
0x00908a79
0x00000001
0x00023af8
0x2fffbf1c
0x00000050
0x2fffac14
0x2fffbf1c

Erase option required for multicast restore
Could not validate source - Device not configured


# First branch in gather_image_metadata
0x00012370 5ED1                   bne        loc_12430

Validating source...
*** ASR Reg-dump @ 0x00012375
0x2fffe0d0
0x0000002f
0x00000000
0x00000000
0x2fffe604
0x2fffe0d0
0x00000000
0x2fffabc4
0x2fffbf1c


# 0x000123e4 gather_image_metadata

Validating source...
*** ASR Reg-dump @ 0x000123e9
0x009076a0
0x00000030
0x00908679
0x00000000
0x009076a0
0x2fffe0d0
0x00022674
0x2fffabc4
0x00000000
Using Hardware AES

Can't gather image metadata
Could not validate source - Authentication error

# 0x00012418
	Validating source...Using Hardware AES
*** ASR Reg-dump @ 0x0001241d
0x00000050
0x00000010
0x00908819
0x00000000
0x009076a0
0x00000050
0x00022674
0x2fffabc4
0x00000000

Can't gather image metadata
Could not validate source - Authentication error

# After patching out call to vectorized validation?

*** ASR Reg-dump @ 0x0001241d
0x00000000
0x009076a0
0x00907640
0x2fffea28
0x009076a0
0x00000000
0x00022674
0x2fffabc4
0x00000000

# 0x00016fd0
	Validating source...Using Hardware AES

Can't gather image metadata
done

*** ASR Reg-dump @ 0x00016fd5
0x00023ae8
0x00000000
0x000007c8
0x00000000
0x00023af8
0x00023ae8
0x00000000
0x2fffbf04
0x2fffbf1c
Bus error

#
Can't gather image metadata
done

*** ASR Reg-dump @ 0x00015529
0x2fffbf1c
0x00000000
0x000007c8
0x00000000
0x00023af8
0x00023ae8
0x00000000
0x2fffbf04
0x2fffbf1c
Bus error

#

Can't gather image metadata
done

*** ASR Reg-dump @ 0x00015591
0x00907d30
0x00000000
0x00000000
0x00000000
0x000226bc
0x00907d30
0x00000000
0x2fffac14
0x2fffbf1c
Segmentation fault

#

*** ASR Reg-dump @ 0x000155d5
0x009083c0
0x00000000
0x00000000
0x00000000
0x009083c0
0x00907d30
0x00000000
0x2fffac14
0x2fffbf1c
Bus error

#

*** ASR Reg-dump @ 0x00010509
0x009075d0
0x00000000
0x00000000
0x0047b4a4
0x00000000
0x00907640
0x009075d0
0x2fffa720
0x00000000

# 

	Validating source...Using Hardware AES

*** ASR Reg-dump @ 0x000106bc
0x00000050
0x00000070
0x00908ca9
0x00000000
0x00907c50
0x00907be0
0x009075d0
0x2fffa720
0x00000000

#

	Validating source...Using Hardware AES

*** ASR Reg-dump @ 0x000106bc
0x00000050
0x00000070
0x00908ca9
0x00000000
0x00907c50
0x00907be0
0x009075d0
0x2fffa720
0x00000000

#

	Validating source...
*** ASR Reg-dump @ 0x000105a2
0x0000004e
0x2fffa6d4
0x00000000
0x00000000
0x00000000
0x00907640
0x009075d0
0x2fffa720
0x00000000
Using Hardware AES


# With invalid

Connected to com.apple.mobile.restored, version 12
Device 8e8366ad7bf1222351522c423aea5fecc9e62793 has successfully entered restore mode
Hardware Information:
BoardID: 0
ChipID: 35120
UniqueChipID: 3727865267063
ProductionMode: true
Previous restore exit status: 0x100
Starting Reverse Proxy
Could not create Reverse Proxy
*** TESTING
common.c:printing 4366 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AutoBootDelay</key>
	<integer>0</integer>
	<key>SupportedDataTypes</key>
	<dict>
		<key>BasebandBootData</key>
		<false/>
		<key>BasebandData</key>
		<false/>
		<key>BasebandStackData</key>
		<false/>
		<key>BasebandUpdaterOutputData</key>
		<false/>
		<key>BootabilityBundle</key>
		<false/>
		<key>BuildIdentityDict</key>
		<false/>
		<key>BuildIdentityDictV2</key>
		<false/>
		<key>Cryptex1LocalPolicy</key>
		<true/>
		<key>DataType</key>
		<false/>
		<key>DiagData</key>
		<false/>
		<key>EANData</key>
		<false/>
		<key>FDRMemoryCommit</key>
		<false/>
		<key>FDRTrustData</key>
		<false/>
		<key>FUDData</key>
		<false/>
		<key>FileData</key>
		<false/>
		<key>FileDataDone</key>
		<false/>
		<key>FirmwareUpdaterData</key>
		<false/>
		<key>GrapeFWData</key>
		<false/>
		<key>HPMFWData</key>
		<false/>
		<key>HostSystemTime</key>
		<true/>
		<key>KernelCache</key>
		<false/>
		<key>NORData</key>
		<false/>
		<key>NitrogenFWData</key>
		<true/>
		<key>OpalFWData</key>
		<false/>
		<key>OverlayRootDataCount</key>
		<false/>
		<key>OverlayRootDataForKey</key>
		<true/>
		<key>PeppyFWData</key>
		<true/>
		<key>PersonalizedBootObjectV3</key>
		<false/>
		<key>PersonalizedData</key>
		<true/>
		<key>ProvisioningData</key>
		<false/>
		<key>RamdiskFWData</key>
		<true/>
		<key>RecoveryOSASRImage</key>
		<true/>
		<key>RecoveryOSAppleLogo</key>
		<true/>
		<key>RecoveryOSDeviceTree</key>
		<true/>
		<key>RecoveryOSFileAssetImage</key>
		<true/>
		<key>RecoveryOSIBEC</key>
		<true/>
		<key>RecoveryOSIBootFWFilesImages</key>
		<true/>
		<key>RecoveryOSImage</key>
		<true/>
		<key>RecoveryOSKernelCache</key>
		<true/>
		<key>RecoveryOSLocalPolicy</key>
		<true/>
		<key>RecoveryOSOverlayRootDataCount</key>
		<false/>
		<key>RecoveryOSRootTicketData</key>
		<true/>
		<key>RecoveryOSStaticTrustCache</key>
		<true/>
		<key>RecoveryOSVersionData</key>
		<true/>
		<key>RootData</key>
		<false/>
		<key>RootTicket</key>
		<false/>
		<key>S3EOverride</key>
		<false/>
		<key>SourceBootObjectV3</key>
		<false/>
		<key>SourceBootObjectV4</key>
		<false/>
		<key>SsoServiceTicket</key>
		<false/>
		<key>StockholmPostflight</key>
		<false/>
		<key>SystemImageCanonicalMetadata</key>
		<false/>
		<key>SystemImageData</key>
		<false/>
		<key>SystemImageRootHash</key>
		<false/>
		<key>USBCFWData</key>
		<false/>
		<key>USBCOverride</key>
		<false/>
		<key>FirmwareUpdaterPreflight</key>
		<true/>
		<key>ReceiptManifest</key>
		<true/>
		<key>FirmwareUpdaterDataV2</key>
		<false/>
		<key>RestoreLocalPolicy</key>
		<true/>
		<key>AuthInstallCACert</key>
		<true/>
		<key>OverlayRootDataForKeyIndex</key>
		<true/>
	</dict>
	<key>SupportedMessageTypes</key>
	<dict>
		<key>BBUpdateStatusMsg</key>
		<false/>
		<key>CheckpointMsg</key>
		<true/>
		<key>DataRequestMsg</key>
		<false/>
		<key>FDRSubmit</key>
		<true/>
		<key>MsgType</key>
		<false/>
		<key>PreviousRestoreLogMsg</key>
		<false/>
		<key>ProgressMsg</key>
		<false/>
		<key>ProvisioningAck</key>
		<false/>
		<key>ProvisioningInfo</key>
		<false/>
		<key>ProvisioningStatusMsg</key>
		<false/>
		<key>ReceivedFinalStatusMsg</key>
		<false/>
		<key>RestoredCrash</key>
		<true/>
		<key>StatusMsg</key>
		<false/>
	</dict>
	<key>BootImageType</key>
	<string>UserOrInternal</string>
	<key>DFUFileType</key>
	<string>RELEASE</string>
	<key>DataImage</key>
	<false/>
	<key>FirmwareDirectory</key>
	<string>.</string>
	<key>FlashNOR</key>
	<true/>
	<key>KernelCacheType</key>
	<string>Release</string>
	<key>NORImageType</key>
	<string>production</string>
	<key>RestoreBundlePath</key>
	<string>/tmp/Per2.tmp</string>
	<key>SystemImageType</key>
	<string>User</string>
	<key>UpdateBaseband</key>
	<false/>
	<key>PersonalizedDuringPreflight</key>
	<true/>
	<key>RootToInstall</key>
	<false/>
	<key>UUID</key>
	<string>62E2E594-38E6-6D6C-D28B-294493F71428</string>
	<key>CreateFilesystemPartitions</key>
	<true/>
	<key>SystemImage</key>
	<true/>
	<key>SystemPartitionPadding</key>
	<dict>
		<key>128</key>
		<integer>1280</integer>
		<key>16</key>
		<integer>160</integer>
		<key>32</key>
		<integer>320</integer>
		<key>64</key>
		<integer>640</integer>
		<key>8</key>
		<integer>80</integer>
	</dict>
</dict>
</plist>
received something from restored
got message
common.c:printing 327 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MsgType</key>
	<string>ProgressMsg</string>
	<key>Operation</key>
	<integer>28</integer>
	<key>Progress</key>
	<integer>-1</integer>
</dict>
</plist>
Waiting for NAND (28)
received something from restored
got message
common.c:printing 327 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MsgType</key>
	<string>ProgressMsg</string>
	<key>Operation</key>
	<integer>11</integer>
	<key>Progress</key>
	<integer>-1</integer>
</dict>
</plist>
Creating partition map (11)
received something from restored
got message
common.c:printing 327 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MsgType</key>
	<string>ProgressMsg</string>
	<key>Operation</key>
	<integer>12</integer>
	<key>Progress</key>
	<integer>-1</integer>
</dict>
</plist>
Creating filesystem (12)
received something from restored
got message
common.c:printing 327 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MsgType</key>
	<string>ProgressMsg</string>
	<key>Operation</key>
	<integer>12</integer>
	<key>Progress</key>
	<integer>-1</integer>
</dict>
</plist>
Creating filesystem (12)
received something from restored
got message
common.c:printing 351 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>DataType</key>
	<string>SystemImageData</string>
	<key>MsgType</key>
	<string>DataRequestMsg</string>
	<key>WillSendImageVerificationProgress</key>
	<true/>
</dict>
</plist>
*** HANDLING restore_handle_data_request_msg type=SystemImageData
*** SystemImageData
About to send filesystem...
Connecting to ASR
Received 235 bytes:
common.c:printing 235 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>Initiate</string>
</dict>
</plist>
Connected to ASR
Validating the filesystem
WAITING...
WAITED!
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>1276</integer>
	<key>OOB Offset</key>
	<integer>569309956</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>72</integer>
	<key>OOB Offset</key>
	<integer>0</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 326 bytes:
common.c:printing 326 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>84</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>1276</integer>
	<key>OOB Offset</key>
	<integer>569309956</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>72</integer>
	<key>OOB Offset</key>
	<integer>0</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 326 bytes:
common.c:printing 326 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>84</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 328 bytes:
common.c:printing 328 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>284</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 328 bytes:
common.c:printing 328 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>900</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 329 bytes:
common.c:printing 329 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>1516</integer>
</dict>
</plist>

# With valid

Connected to com.apple.mobile.restored, version 12
Device 8e8366ad7bf1222351522c423aea5fecc9e62793 has successfully entered restore mode
Hardware Information:
BoardID: 0
ChipID: 35120
UniqueChipID: 3727865267063
ProductionMode: true
Previous restore exit status: 0x100
Starting Reverse Proxy
Could not create Reverse Proxy
*** TESTING
common.c:printing 4366 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>AutoBootDelay</key>
	<integer>0</integer>
	<key>SupportedDataTypes</key>
	<dict>
		<key>BasebandBootData</key>
		<false/>
		<key>BasebandData</key>
		<false/>
		<key>BasebandStackData</key>
		<false/>
		<key>BasebandUpdaterOutputData</key>
		<false/>
		<key>BootabilityBundle</key>
		<false/>
		<key>BuildIdentityDict</key>
		<false/>
		<key>BuildIdentityDictV2</key>
		<false/>
		<key>Cryptex1LocalPolicy</key>
		<true/>
		<key>DataType</key>
		<false/>
		<key>DiagData</key>
		<false/>
		<key>EANData</key>
		<false/>
		<key>FDRMemoryCommit</key>
		<false/>
		<key>FDRTrustData</key>
		<false/>
		<key>FUDData</key>
		<false/>
		<key>FileData</key>
		<false/>
		<key>FileDataDone</key>
		<false/>
		<key>FirmwareUpdaterData</key>
		<false/>
		<key>GrapeFWData</key>
		<false/>
		<key>HPMFWData</key>
		<false/>
		<key>HostSystemTime</key>
		<true/>
		<key>KernelCache</key>
		<false/>
		<key>NORData</key>
		<false/>
		<key>NitrogenFWData</key>
		<true/>
		<key>OpalFWData</key>
		<false/>
		<key>OverlayRootDataCount</key>
		<false/>
		<key>OverlayRootDataForKey</key>
		<true/>
		<key>PeppyFWData</key>
		<true/>
		<key>PersonalizedBootObjectV3</key>
		<false/>
		<key>PersonalizedData</key>
		<true/>
		<key>ProvisioningData</key>
		<false/>
		<key>RamdiskFWData</key>
		<true/>
		<key>RecoveryOSASRImage</key>
		<true/>
		<key>RecoveryOSAppleLogo</key>
		<true/>
		<key>RecoveryOSDeviceTree</key>
		<true/>
		<key>RecoveryOSFileAssetImage</key>
		<true/>
		<key>RecoveryOSIBEC</key>
		<true/>
		<key>RecoveryOSIBootFWFilesImages</key>
		<true/>
		<key>RecoveryOSImage</key>
		<true/>
		<key>RecoveryOSKernelCache</key>
		<true/>
		<key>RecoveryOSLocalPolicy</key>
		<true/>
		<key>RecoveryOSOverlayRootDataCount</key>
		<false/>
		<key>RecoveryOSRootTicketData</key>
		<true/>
		<key>RecoveryOSStaticTrustCache</key>
		<true/>
		<key>RecoveryOSVersionData</key>
		<true/>
		<key>RootData</key>
		<false/>
		<key>RootTicket</key>
		<false/>
		<key>S3EOverride</key>
		<false/>
		<key>SourceBootObjectV3</key>
		<false/>
		<key>SourceBootObjectV4</key>
		<false/>
		<key>SsoServiceTicket</key>
		<false/>
		<key>StockholmPostflight</key>
		<false/>
		<key>SystemImageCanonicalMetadata</key>
		<false/>
		<key>SystemImageData</key>
		<false/>
		<key>SystemImageRootHash</key>
		<false/>
		<key>USBCFWData</key>
		<false/>
		<key>USBCOverride</key>
		<false/>
		<key>FirmwareUpdaterPreflight</key>
		<true/>
		<key>ReceiptManifest</key>
		<true/>
		<key>FirmwareUpdaterDataV2</key>
		<false/>
		<key>RestoreLocalPolicy</key>
		<true/>
		<key>AuthInstallCACert</key>
		<true/>
		<key>OverlayRootDataForKeyIndex</key>
		<true/>
	</dict>
	<key>SupportedMessageTypes</key>
	<dict>
		<key>BBUpdateStatusMsg</key>
		<false/>
		<key>CheckpointMsg</key>
		<true/>
		<key>DataRequestMsg</key>
		<false/>
		<key>FDRSubmit</key>
		<true/>
		<key>MsgType</key>
		<false/>
		<key>PreviousRestoreLogMsg</key>
		<false/>
		<key>ProgressMsg</key>
		<false/>
		<key>ProvisioningAck</key>
		<false/>
		<key>ProvisioningInfo</key>
		<false/>
		<key>ProvisioningStatusMsg</key>
		<false/>
		<key>ReceivedFinalStatusMsg</key>
		<false/>
		<key>RestoredCrash</key>
		<true/>
		<key>StatusMsg</key>
		<false/>
	</dict>
	<key>BootImageType</key>
	<string>UserOrInternal</string>
	<key>DFUFileType</key>
	<string>RELEASE</string>
	<key>DataImage</key>
	<false/>
	<key>FirmwareDirectory</key>
	<string>.</string>
	<key>FlashNOR</key>
	<true/>
	<key>KernelCacheType</key>
	<string>Release</string>
	<key>NORImageType</key>
	<string>production</string>
	<key>RestoreBundlePath</key>
	<string>/tmp/Per2.tmp</string>
	<key>SystemImageType</key>
	<string>User</string>
	<key>UpdateBaseband</key>
	<false/>
	<key>PersonalizedDuringPreflight</key>
	<true/>
	<key>RootToInstall</key>
	<false/>
	<key>UUID</key>
	<string>7C4087E8-B9B2-5498-FB59-95AC014D7D0F</string>
	<key>CreateFilesystemPartitions</key>
	<true/>
	<key>SystemImage</key>
	<true/>
	<key>SystemPartitionPadding</key>
	<dict>
		<key>128</key>
		<integer>1280</integer>
		<key>16</key>
		<integer>160</integer>
		<key>32</key>
		<integer>320</integer>
		<key>64</key>
		<integer>640</integer>
		<key>8</key>
		<integer>80</integer>
	</dict>
</dict>
</plist>
received something from restored
got message
common.c:printing 327 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MsgType</key>
	<string>ProgressMsg</string>
	<key>Operation</key>
	<integer>28</integer>
	<key>Progress</key>
	<integer>-1</integer>
</dict>
</plist>
Waiting for NAND (28)
received something from restored
got message
common.c:printing 327 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MsgType</key>
	<string>ProgressMsg</string>
	<key>Operation</key>
	<integer>11</integer>
	<key>Progress</key>
	<integer>-1</integer>
</dict>
</plist>
Creating partition map (11)
received something from restored
got message
common.c:printing 327 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MsgType</key>
	<string>ProgressMsg</string>
	<key>Operation</key>
	<integer>12</integer>
	<key>Progress</key>
	<integer>-1</integer>
</dict>
</plist>
Creating filesystem (12)
received something from restored
got message
common.c:printing 327 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>MsgType</key>
	<string>ProgressMsg</string>
	<key>Operation</key>
	<integer>12</integer>
	<key>Progress</key>
	<integer>-1</integer>
</dict>
</plist>
Creating filesystem (12)
received something from restored
got message
common.c:printing 351 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>DataType</key>
	<string>SystemImageData</string>
	<key>MsgType</key>
	<string>DataRequestMsg</string>
	<key>WillSendImageVerificationProgress</key>
	<true/>
</dict>
</plist>
*** HANDLING restore_handle_data_request_msg type=SystemImageData
*** SystemImageData
About to send filesystem...
Connecting to ASR
Retrying connection...
Received 272 bytes:
common.c:printing 272 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Checksum Chunks</key>
	<true/>
	<key>Command</key>
	<string>Initiate</string>
</dict>
</plist>
Connected to ASR
Validating the filesystem
WAITING...
WAITED!
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>1276</integer>
	<key>OOB Offset</key>
	<integer>569309956</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>72</integer>
	<key>OOB Offset</key>
	<integer>0</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 326 bytes:
common.c:printing 326 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>84</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>1276</integer>
	<key>OOB Offset</key>
	<integer>569309956</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>72</integer>
	<key>OOB Offset</key>
	<integer>0</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 326 bytes:
common.c:printing 326 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>84</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 328 bytes:
common.c:printing 328 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>284</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 328 bytes:
common.c:printing 328 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>900</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 329 bytes:
common.c:printing 329 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>1516</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569073664</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 337 bytes:
common.c:printing 337 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>229376</integer>
	<key>OOB Offset</key>
	<integer>569077760</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>1276</integer>
	<key>OOB Offset</key>
	<integer>569309956</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>72</integer>
	<key>OOB Offset</key>
	<integer>0</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 326 bytes:
common.c:printing 326 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>84</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>1276</integer>
	<key>OOB Offset</key>
	<integer>569309956</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>72</integer>
	<key>OOB Offset</key>
	<integer>0</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 326 bytes:
common.c:printing 326 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>84</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 328 bytes:
common.c:printing 328 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>284</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 328 bytes:
common.c:printing 328 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>900</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 329 bytes:
common.c:printing 329 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>1516</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569073664</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 337 bytes:
common.c:printing 337 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>229376</integer>
	<key>OOB Offset</key>
	<integer>569077760</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 334 bytes:
common.c:printing 334 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>67321856</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 336 bytes:
common.c:printing 336 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>159744</integer>
	<key>OOB Offset</key>
	<integer>67325952</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 334 bytes:
common.c:printing 334 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>67485696</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>1276</integer>
	<key>OOB Offset</key>
	<integer>569309956</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>72</integer>
	<key>OOB Offset</key>
	<integer>0</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 326 bytes:
common.c:printing 326 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>84</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>1276</integer>
	<key>OOB Offset</key>
	<integer>569309956</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 325 bytes:
common.c:printing 325 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>72</integer>
	<key>OOB Offset</key>
	<integer>0</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 326 bytes:
common.c:printing 326 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>84</integer>
	<key>OOB Offset</key>
	<integer>72</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 328 bytes:
common.c:printing 328 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>284</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 328 bytes:
common.c:printing 328 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>900</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 329 bytes:
common.c:printing 329 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>616</integer>
	<key>OOB Offset</key>
	<integer>1516</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 332 bytes:
common.c:printing 332 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>122880</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569073664</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 337 bytes:
common.c:printing 337 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>229376</integer>
	<key>OOB Offset</key>
	<integer>569077760</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569073664</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 337 bytes:
common.c:printing 337 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>229376</integer>
	<key>OOB Offset</key>
	<integer>569077760</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 335 bytes:
common.c:printing 335 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>OOBData</string>
	<key>OOB Length</key>
	<integer>4096</integer>
	<key>OOB Offset</key>
	<integer>569307136</integer>
</dict>
</plist>
Retval of asr_receive: 0
Received 234 bytes:
common.c:printing 234 bytes plist:
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Command</key>
	<string>Payload</string>
</dict>
</plist>
Retval of asr_receive: 0
Filesystem validated
Sending filesystem now...
[===================                               ]  37.0%