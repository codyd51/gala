#!/bin/bash
xcrun -sdk /Users/philliptennen/Documents/Jailbreak/iPhoneSDK4_0.pkg.unzipped/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk clang -arch armv7 -mios-version-min=4.0 umount.m -o umount -L./ -framework CoreFoundation
scp -P 2222 -o StrictHostKeyChecking=no -oHostKeyAlgorithms=+ssh-dss ./umount root@localhost:/usr/bin/umount
ssh -oHostKeyAlgorithms=+ssh-dss root@localhost -p 2222
