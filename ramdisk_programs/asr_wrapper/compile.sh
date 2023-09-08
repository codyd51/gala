#!/bin/bash
SDK=/Users/philliptennen/Documents/Jailbreak/iPhoneSDK4_0.pkg.unzipped/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk
xcrun -sdk $SDK clang -arch armv7 -mios-version-min=4.0 asr_wrapper.m -o build/asr_wrapper -L./ -F$SDK/System/Library/PrivateFrameworks/ -framework CoreFoundation -framework IOKit -framework IOMobileFramebuffer -framework CoreGraphics -framework IOSurface -framework CoreFoundation -framework CoreSurface -lobjc -framework ImageIO
sshpass -p "alpine" scp -P 2222 -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-dss ./build/asr_wrapper root@localhost:/usr/bin/asr_wrapper
#ssh -oHostKeyAlgorithms=+ssh-dss root@localhost -p 2222
