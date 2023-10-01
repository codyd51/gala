#!/bin/bash
xcrun -sdk ../../iPhoneSDK4_0/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk clang -arch armv7 -mios-version-min=4.0 umount.m -o build/umount -L./ -framework CoreFoundation
