from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

from strongarm.macho import VirtualMemoryPointer

from utils import TotalEnumMapping


class DeviceModel(Enum):
    iPhone3_1 = auto()


class ImageType(Enum):
    iBSS = auto()
    iBEC = auto()
    AppleLogo = auto()

    @property
    def base_address(self) -> VirtualMemoryPointer:
        return TotalEnumMapping({
            ImageType.iBSS: VirtualMemoryPointer(0x84000000),
            # TODO(PT): This may be incorrect?
            ImageType.iBEC: VirtualMemoryPointer(0x43000000),
            ImageType.AppleLogo: VirtualMemoryPointer(0x0),
        })[self]


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
        return TotalEnumMapping({
            DeviceModel.iPhone3_1: TotalEnumMapping({
                ImageType.iBSS: Path("Firmware") / "dfu" / "iBSS.n90ap.RELEASE.dfu",
                ImageType.iBEC: Path("Firmware") / "dfu" / "iBEC.n90ap.RELEASE.dfu",
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
            )
        }),
        OsBuildEnum.iPhone3_1_4_1_8B117: TotalEnumMapping({
            ImageType.iBSS: KeyIvPair(
                key="1fbc7dcafaec21a150a51eb0eb99367550e24a077b128831b28c065e61f894a0",
                iv="c2c5416472e5a0d6f0a25a123d5a2b1c",
            ),
            ImageType.iBEC: KeyIvPair(
                key="71fc41981edea73b324edfa22585a0f7cb888f370239e36262832f8df9018e85",
                iv="fe47eae4d54b1d02f096e694e21f2967",
            )
        }),
        OsBuildEnum.iPhone3_1_5_0_9A334: TotalEnumMapping({
            ImageType.iBSS: KeyIvPair(
                key="dc5e8dcd58628a25865fb77c2fddb9d2a17f7c933aa27c53ce2d8c4173d6a8da",
                iv="afd80e647e22d22a26b6e58fb5846823",
            ),
            ImageType.iBEC: KeyIvPair(
                key="240580fa75a672a810100daec3bfc0cd189270c621e575b469e02e62029de12b",
                iv="d435f60732b322140217f21f1589b8b4",
            )
        }),
        OsBuildEnum.iPhone3_1_6_1_10B144: TotalEnumMapping({
            ImageType.iBSS: KeyIvPair(
                key="f7f5fd61ea0792f13ea84126c3afe33944ddc543b62b552e009cbffaf7e34e28",
                iv="24af28537e544ebf981ce32708a7e21f",
            ),
            ImageType.iBEC: KeyIvPair(
                key="061695b0ba878657ae195416cff88287f222b50baabb9f72e0c2271db6b58db5",
                iv="1168b9ddb4c5df062892810fec574f55",
            )
        }),
    })

    @classmethod
    def key_iv_pair_for_image(cls, os_build: OsBuildEnum, image_type: ImageType) -> KeyIvPair:
        os_build_keys = cls._BUILDS_TO_IMAGE_KEY_PAIRS[os_build]
        return os_build_keys[image_type]

