#!/bin/bash
xcrun -sdk "$(pwd)"/../../sdks/iPhone3,1_4.0_8A293/iPhoneOS4.0.sdk clang -arch armv7 -mios-version-min=4.0 umount.m -o build/umount -L./ -framework CoreFoundation
