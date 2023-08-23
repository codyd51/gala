#!/bin/bash
xcrun -sdk /Users/philliptennen/Documents/Jailbreak/iPhoneSDK4_0.pkg.unzipped/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk clang -arch armv7 -mios-version-min=4.0 inject_test.m -o build/inject_test -L./ -framework CoreFoundation
sshpass -p "alpine" scp -P 2222 -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-dss ./build/inject_test root@localhost:/inject_test
#ssh -oHostKeyAlgorithms=+ssh-dss root@localhost -p 2222
