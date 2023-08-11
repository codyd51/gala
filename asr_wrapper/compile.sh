#!/bin/bash
xcrun -sdk /Users/philliptennen/Documents/Jailbreak/iPhoneSDK4_0.pkg.unzipped/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk clang -arch armv7 -mios-version-min=4.0 asr_wrapper.m -o build/asr_wrapper -L./ -framework CoreFoundation
#scp -P 2222 -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-dss ./build/asr_wrapper root@localhost:/usr/bin/asr_wrapper
#ssh -oHostKeyAlgorithms=+ssh-dss root@localhost -p 2222
