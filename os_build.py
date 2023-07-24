from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any

from strongarm.macho import VirtualMemoryPointer

from utils import TotalEnumMapping


class DeviceModel(Enum):
    iPhone3_1 = auto()


class ImageType(Enum):
    iBSS = auto()
    iBEC = auto()
    AppleLogo = auto()
    KernelCache = auto()
    RestoreRamdisk = auto()

    @property
    def base_address(self) -> VirtualMemoryPointer:
        # TODO(PT): Remove this, it only applies to raw binary images
        # Maybe there's a method on an image handle that'll automatically pull it if it's a Mach-O?
        return TotalEnumMapping({
            ImageType.iBSS: VirtualMemoryPointer(0x84000000),
            # TODO(PT): This may be incorrect?
            ImageType.iBEC: VirtualMemoryPointer(0x5ff00000),
            ImageType.AppleLogo: VirtualMemoryPointer(0x0),
            ImageType.KernelCache: VirtualMemoryPointer(0x80001000),
            # PT: Not relevant for ramdisks?
            ImageType.RestoreRamdisk: VirtualMemoryPointer(0x0),
        })[self]

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
    def ramdisk_types(cls) -> list[ImageType]:
        return [
            ImageType.RestoreRamdisk,
        ]

    @classmethod
    def validate_type_subsets(cls):
        all_types = {t for t in ImageType}
        binary_types = set(cls.binary_types())
        picture_types = set(cls.picture_types())
        ramdisk_types = set(cls.ramdisk_types())
        categories = [binary_types, picture_types, ramdisk_types]
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
    def binary_types_mapping(cls, mapping: dict[ImageType, Any]):
        # TODO(PT): Perhaps instead we could have a special 'inject PNG' patch, rather than having a totally
        # separate code path for pictures
        return TotalEnumMapping(mapping, omitted_variants=ImageType.picture_types())


# Post-class construction validation to sanity check the image type subsets
# Unfortunately, Python doesn't let us easily scope this within the class itself
ImageType.validate_type_subsets()


class OsBuildEnum(Enum):
    iPhone3_1_4_0_8A293 = auto()
    iPhone3_1_4_1_8B117 = auto()
    iPhone3_1_5_0_9A334 = auto()
    iPhone3_1_6_1_10B144 = auto()

    @property
    def unescaped_name(self):
        return TotalEnumMapping({
            OsBuildEnum.iPhone3_1_4_0_8A293: "iPhone3,1_4.0_8A293",
            OsBuildEnum.iPhone3_1_4_1_8B117: "iPhone3,1_4.1_8B117",
            OsBuildEnum.iPhone3_1_5_0_9A334: "iPhone3,1_5.0_9A334",
            OsBuildEnum.iPhone3_1_6_1_10B144: "iPhone3,1_6.1_10B144",
        })[self]

    @property
    def model(self) -> DeviceModel:
        return TotalEnumMapping({
            OsBuildEnum.iPhone3_1_4_0_8A293: DeviceModel.iPhone3_1,
            OsBuildEnum.iPhone3_1_4_1_8B117: DeviceModel.iPhone3_1,
            OsBuildEnum.iPhone3_1_5_0_9A334: DeviceModel.iPhone3_1,
            OsBuildEnum.iPhone3_1_6_1_10B144: DeviceModel.iPhone3_1,
        })[self]

    def ipsw_path_for_image_type(self, image_type: ImageType) -> Path:
        # PT: Perhaps we can read all of these paths from the `BuildManifest.plist`/`Restore.plist`?
        return TotalEnumMapping({
            DeviceModel.iPhone3_1: TotalEnumMapping({
                ImageType.iBSS: Path("Firmware") / "dfu" / "iBSS.n90ap.RELEASE.dfu",
                ImageType.iBEC: Path("Firmware") / "dfu" / "iBEC.n90ap.RELEASE.dfu",
                ImageType.AppleLogo: (
                    Path("Firmware") / "all_flash" / "all_flash.n90ap.production" / "applelogo-640x960.s5l8930x.img3"
                ),
                ImageType.KernelCache: Path("kernelcache.release.n90"),
                ImageType.RestoreRamdisk: Path("018-6306-403.dmg"),
            }),
        })[self.model][image_type]


@dataclass
class KeyIvPair:
    key: str
    iv: str


class KeyRepository:
    _BUILDS_TO_IMAGE_KEY_PAIRS = TotalEnumMapping({
        OsBuildEnum.iPhone3_1_4_0_8A293: TotalEnumMapping({
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
        }),
        OsBuildEnum.iPhone3_1_4_1_8B117: TotalEnumMapping({
            ImageType.iBSS: KeyIvPair(
                key="1fbc7dcafaec21a150a51eb0eb99367550e24a077b128831b28c065e61f894a0",
                iv="c2c5416472e5a0d6f0a25a123d5a2b1c",
            ),
            ImageType.iBEC: KeyIvPair(
                key="71fc41981edea73b324edfa22585a0f7cb888f370239e36262832f8df9018e85",
                iv="fe47eae4d54b1d02f096e694e21f2967",
            ),
            ImageType.AppleLogo: KeyIvPair(key="", iv=""),
            ImageType.KernelCache: KeyIvPair(key="", iv=""),
            ImageType.RestoreRamdisk: KeyIvPair(key="", iv=""),
        }),
        OsBuildEnum.iPhone3_1_5_0_9A334: TotalEnumMapping({
            ImageType.iBSS: KeyIvPair(
                key="dc5e8dcd58628a25865fb77c2fddb9d2a17f7c933aa27c53ce2d8c4173d6a8da",
                iv="afd80e647e22d22a26b6e58fb5846823",
            ),
            ImageType.iBEC: KeyIvPair(
                key="240580fa75a672a810100daec3bfc0cd189270c621e575b469e02e62029de12b",
                iv="d435f60732b322140217f21f1589b8b4",
            ),
            ImageType.AppleLogo: KeyIvPair(key="", iv=""),
            ImageType.KernelCache: KeyIvPair(key="", iv=""),
            ImageType.RestoreRamdisk: KeyIvPair(key="", iv=""),
        }),
        OsBuildEnum.iPhone3_1_6_1_10B144: TotalEnumMapping({
            ImageType.iBSS: KeyIvPair(
                key="f7f5fd61ea0792f13ea84126c3afe33944ddc543b62b552e009cbffaf7e34e28",
                iv="24af28537e544ebf981ce32708a7e21f",
            ),
            ImageType.iBEC: KeyIvPair(
                key="061695b0ba878657ae195416cff88287f222b50baabb9f72e0c2271db6b58db5",
                iv="1168b9ddb4c5df062892810fec574f55",
            ),
            ImageType.AppleLogo: KeyIvPair(key="", iv=""),
            ImageType.KernelCache: KeyIvPair(key="", iv=""),
            ImageType.RestoreRamdisk: KeyIvPair(key="", iv=""),
        }),
    })

    @classmethod
    def key_iv_pair_for_image(cls, os_build: OsBuildEnum, image_type: ImageType) -> KeyIvPair:
        os_build_keys = cls._BUILDS_TO_IMAGE_KEY_PAIRS[os_build]
        return os_build_keys[image_type]

