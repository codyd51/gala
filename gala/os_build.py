from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from enum import auto
from pathlib import Path
from typing import Any, Tuple
from typing import Mapping

from strongarm.macho import VirtualMemoryPointer

from gala.utils import TotalEnumMapping


class DeviceModel(Enum):
    iPhone3_1 = auto()


class ImageType(Enum):
    # Images within the IPSW
    iBSS = auto()
    iBEC = auto()
    AppleLogo = auto()
    KernelCache = auto()
    RestoreRamdisk = auto()
    RootFilesystem = auto()
    # Images that we provide as part of the bootstrap
    MobileSubstrate = auto()

    @property
    def base_address(self) -> VirtualMemoryPointer:
        # TODO(PT): Remove this, it only applies to raw binary images
        # Maybe there's a method on an image handle that'll automatically pull it if it's a Mach-O?
        return TotalEnumMapping(
            {
                ImageType.iBSS: VirtualMemoryPointer(0x84000000),
                # TODO(PT): This may be incorrect?
                ImageType.iBEC: VirtualMemoryPointer(0x5FF00000),
                ImageType.AppleLogo: VirtualMemoryPointer(0x0),
                ImageType.KernelCache: VirtualMemoryPointer(0x80001000),
                # PT: Not relevant for ramdisks?
                ImageType.RestoreRamdisk: VirtualMemoryPointer(0x0),
                ImageType.RootFilesystem: VirtualMemoryPointer(0x0),
                ImageType.MobileSubstrate: VirtualMemoryPointer(0x0),
            }
        )[self]

    @classmethod
    def picture_types(cls) -> list[ImageType]:
        return [ImageType.AppleLogo]

    @classmethod
    def binary_types(cls) -> list[ImageType]:
        return [
            ImageType.iBSS,
            ImageType.iBEC,
            ImageType.KernelCache,
        ]

    @classmethod
    def dmg_types(cls) -> list[ImageType]:
        return [
            ImageType.RestoreRamdisk,
            ImageType.RootFilesystem,
        ]

    @classmethod
    def deb_types(cls) -> list[ImageType]:
        return [
            ImageType.MobileSubstrate,
        ]

    @classmethod
    def validate_type_subsets(cls) -> None:
        all_types = {t for t in ImageType}
        categories = [
            set(x)
            for x in [
                cls.binary_types(),
                cls.picture_types(),
                cls.dmg_types(),
                cls.deb_types(),
            ]
        ]
        all_types_by_category = set.union(*categories)

        # Ensure the union of the categorized image types cover all defined image types
        if all_types_by_category != all_types:
            raise ValueError("The union of categorized types didn't yield all image types")

        # Ensure there's no overlap between different categories of image types
        for category1 in categories:
            for category2 in categories:
                if category1 == category2:
                    # Don't compare a category to itself
                    continue
                if not category1.isdisjoint(category2):
                    raise ValueError("All image categories must be disjoint with each other")

    @classmethod
    def _mapping_total_over_subkeys(
        cls, mapping: dict[ImageType, Any], subkeys: list[ImageType]
    ) -> Mapping[ImageType, Any]:
        return TotalEnumMapping(mapping, omitted_variants=[x for x in ImageType if x not in subkeys])

    @classmethod
    def binary_types_mapping(cls, mapping: dict[ImageType, Any]) -> Any:
        # TODO(PT): Perhaps instead we could have a special 'inject PNG' patch, rather than having a totally
        # separate code path for pictures
        return cls._mapping_total_over_subkeys(mapping, ImageType.binary_types())

    @classmethod
    def deb_types_mapping(cls, mapping: dict[ImageType, Any]) -> Any:
        return cls._mapping_total_over_subkeys(mapping, ImageType.deb_types())

    @classmethod
    def dmg_types_mapping(cls, mapping: dict[ImageType, Any]) -> Any:
        return cls._mapping_total_over_subkeys(mapping, ImageType.dmg_types())

    @classmethod
    def picture_types_mapping(cls, mapping: dict[ImageType, Any]) -> Any:
        return cls._mapping_total_over_subkeys(mapping, ImageType.picture_types())


# Post-class construction validation to sanity check the image type subsets
# Unfortunately, Python doesn't let us easily scope this within the class itself
ImageType.validate_type_subsets()


@dataclass
class XcodeDownloadInfo:
    download_name: str
    download_url: str
    interior_sdk_package_path: Path
    sdk_path_within_sdk_package: Path


class OsBuildEnum(Enum):
    iPhone3_1_4_0_8A293 = auto()
    iPhone3_1_4_1_8B117 = auto()
    iPhone3_1_5_0_9A334 = auto()
    iPhone3_1_6_1_10B144 = auto()

    @property
    def unescaped_name(self) -> str:
        return TotalEnumMapping(
            {
                OsBuildEnum.iPhone3_1_4_0_8A293: "iPhone3,1_4.0_8A293",
                OsBuildEnum.iPhone3_1_4_1_8B117: "iPhone3,1_4.1_8B117",
                OsBuildEnum.iPhone3_1_5_0_9A334: "iPhone3,1_5.0_9A334",
                OsBuildEnum.iPhone3_1_6_1_10B144: "iPhone3,1_6.1_10B144",
            }
        )[self]

    @property
    def model(self) -> DeviceModel:
        return TotalEnumMapping(
            {
                OsBuildEnum.iPhone3_1_4_0_8A293: DeviceModel.iPhone3_1,
                OsBuildEnum.iPhone3_1_4_1_8B117: DeviceModel.iPhone3_1,
                OsBuildEnum.iPhone3_1_5_0_9A334: DeviceModel.iPhone3_1,
                OsBuildEnum.iPhone3_1_6_1_10B144: DeviceModel.iPhone3_1,
            }
        )[self]

    def ipsw_path_for_image_type(self, image_type: ImageType) -> Path:
        # PT: Perhaps we can read all of these paths from the `BuildManifest.plist`/`Restore.plist`?
        return TotalEnumMapping(
            {
                DeviceModel.iPhone3_1: TotalEnumMapping(
                    {
                        ImageType.iBSS: Path("Firmware") / "dfu" / "iBSS.n90ap.RELEASE.dfu",
                        ImageType.iBEC: Path("Firmware") / "dfu" / "iBEC.n90ap.RELEASE.dfu",
                        ImageType.AppleLogo: (
                            Path("Firmware")
                            / "all_flash"
                            / "all_flash.n90ap.production"
                            / "applelogo-640x960.s5l8930x.img3"
                        ),
                        ImageType.KernelCache: Path("kernelcache.release.n90"),
                        # TODO(PT): I think these names might also vary by OS build...
                        ImageType.RestoreRamdisk: Path("018-6306-403.dmg"),
                        ImageType.RootFilesystem: Path("018-6303-385.dmg"),
                    },
                    # .debs aren't stored within the IPSW
                    omitted_variants=ImageType.deb_types(),
                ),
            }
        )[self.model][image_type]

    def asset_path_for_image_type(self, image_type: ImageType) -> Path:
        from gala.configuration import ASSETS_ROOT

        # This only applies to .debs, which are stored in assets/ instead of in an IPSW
        return TotalEnumMapping(
            {
                DeviceModel.iPhone3_1: ImageType.deb_types_mapping(
                    {
                        ImageType.MobileSubstrate: ASSETS_ROOT / "mobilesubstrate_0.9.6301_iphoneos-arm.deb",
                    }
                ),
            }
        )[self.model][image_type]

    @property
    def download_url(self) -> str:
        def not_implemented() -> None:
            raise NotImplementedError()

        # PT: This map is callback-based as a small trick to stay total without needing to define all the URLs at once
        return TotalEnumMapping(
            {
                self.iPhone3_1_4_0_8A293: lambda: (
                    "https://secure-appldnld.apple.com/iPhone4/061-7380.20100621,Vfgb5/iPhone3,1_4.0_8A293_Restore.ipsw"
                ),
                self.iPhone3_1_4_1_8B117: not_implemented,
                self.iPhone3_1_5_0_9A334: not_implemented,
                self.iPhone3_1_6_1_10B144: not_implemented,
            }
        )[
            self  # type: ignore
        ]()

    @property
    def sdk_download_info(self) -> XcodeDownloadInfo:
        def not_implemented() -> None:
            raise NotImplementedError()

        # PT: This map is callback-based as a small trick to stay total without needing to define all the URLs at once
        return TotalEnumMapping(
            {
                self.iPhone3_1_4_0_8A293: lambda: (
                    # PT: This is the iOS 4.0.1 SDK instead of 4.0, but it's close enough for our purposes
                    XcodeDownloadInfo(
                        download_name="Xcode 3.2.3 and iOS SDK 4.0.1",
                        download_url="https://download.developer.apple.com/ios/ios_sdk_4.0.1__final/xcode_3.2.3_and_ios_sdk_4.0.1.dmg",
                        interior_sdk_package_path=Path("Packages") / "iPhoneSDK4_0.pkg",
                        sdk_path_within_sdk_package=Path("Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS4.0.sdk"),
                    )
                ),
                self.iPhone3_1_4_1_8B117: not_implemented,
                self.iPhone3_1_5_0_9A334: not_implemented,
                self.iPhone3_1_6_1_10B144: not_implemented,
            }
        )[
            self  # type: ignore
        ]()


@dataclass
class KeyIvPair:
    key: str
    iv: str


class KeyRepository:
    _BUILDS_TO_IMAGE_KEY_PAIRS = TotalEnumMapping(
        {
            OsBuildEnum.iPhone3_1_4_0_8A293: TotalEnumMapping(
                {
                    ImageType.iBSS: KeyIvPair(
                        key="d05c3c40db40e738926f811b8b1314038d26096c4102461698a49098c47a3fe6",
                        iv="91f94e5d726a2d2f2c7ffad58d4f3b77",
                    ),
                    ImageType.iBEC: KeyIvPair(
                        key="15d7ef3c974c6afcdf08d575c4bbfdcef260751667ae5fc2006f10ce5b03bb2d",
                        iv="3cde603259045d2dcc7f70bd39b9d8e9",
                    ),
                    ImageType.AppleLogo: KeyIvPair(
                        key="0feb8e5306e2a529e4f7b39e24fc49e90669c15c218d29c55ac734f7516c5519",
                        iv="eab39b46e705b57f820beeea28ea051e",
                    ),
                    ImageType.KernelCache: KeyIvPair(
                        key="f241daee7e32a7caf99d55fa0ab17e41501d03d69fe2e02b57688d0b1781e659",
                        iv="8e4c493706b43f9fd92021126bebfeda",
                    ),
                    ImageType.RestoreRamdisk: KeyIvPair(
                        key="62aabe3e763eb3669b4922468be2acb787199c6b0ef8ae873c312e458d9b9be3",
                        iv="0ab135879934fdd0d689b3d0f8cf8374",
                    ),
                    ImageType.RootFilesystem: KeyIvPair(
                        key="8b2915719d9f90ba5521faad1eadbb3d942991bd55e5a0709f26e9db3931517e054afa50",
                        # PT: IV isn't applicable for the root filesystem? Perhaps the `iv` needs to be optional?
                        iv="",
                    ),
                },
                omitted_variants=ImageType.deb_types(),
            ),
            OsBuildEnum.iPhone3_1_4_1_8B117: TotalEnumMapping(
                {
                    ImageType.iBSS: KeyIvPair(key="", iv=""),
                    ImageType.iBEC: KeyIvPair(key="", iv=""),
                    ImageType.AppleLogo: KeyIvPair(key="", iv=""),
                    ImageType.KernelCache: KeyIvPair(key="", iv=""),
                    ImageType.RestoreRamdisk: KeyIvPair(key="", iv=""),
                    ImageType.RootFilesystem: KeyIvPair(key="", iv=""),
                },
                omitted_variants=ImageType.deb_types(),
            ),
            OsBuildEnum.iPhone3_1_5_0_9A334: TotalEnumMapping(
                {
                    ImageType.iBSS: KeyIvPair(key="", iv=""),
                    ImageType.iBEC: KeyIvPair(key="", iv=""),
                    ImageType.AppleLogo: KeyIvPair(key="", iv=""),
                    ImageType.KernelCache: KeyIvPair(key="", iv=""),
                    ImageType.RestoreRamdisk: KeyIvPair(key="", iv=""),
                    ImageType.RootFilesystem: KeyIvPair(key="", iv=""),
                },
                omitted_variants=ImageType.deb_types(),
            ),
            OsBuildEnum.iPhone3_1_6_1_10B144: TotalEnumMapping(
                {
                    ImageType.iBSS: KeyIvPair(key="", iv=""),
                    ImageType.iBEC: KeyIvPair(key="", iv=""),
                    ImageType.AppleLogo: KeyIvPair(key="", iv=""),
                    ImageType.KernelCache: KeyIvPair(key="", iv=""),
                    ImageType.RestoreRamdisk: KeyIvPair(key="", iv=""),
                    ImageType.RootFilesystem: KeyIvPair(key="", iv=""),
                },
                omitted_variants=ImageType.deb_types(),
            ),
        }
    )

    @classmethod
    def key_iv_pair_for_image(cls, os_build: OsBuildEnum, image_type: ImageType) -> KeyIvPair:
        os_build_keys = cls._BUILDS_TO_IMAGE_KEY_PAIRS[os_build]
        return os_build_keys[image_type]
