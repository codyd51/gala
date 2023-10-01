#!/bin/bash
SDK="$(pwd)"/../../sdks/iPhone3,1_4.0_8A293/iPhoneOS4.0.sdk
xcrun -sdk $SDK clang -arch armv7 -mios-version-min=4.0 asr_wrapper.m -o build/asr_wrapper -L./ -F$SDK/System/Library/PrivateFrameworks/ -framework CoreFoundation -framework IOKit -framework IOMobileFramebuffer -framework CoreGraphics -framework IOSurface -framework CoreFoundation -framework CoreSurface -lobjc -framework ImageIO
sshpass -p "alpine" scp -P 2222 -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-dss ./build/asr_wrapper root@localhost:/usr/bin/asr_wrapper
