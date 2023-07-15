from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path

from utils import TotalEnumMapping


class DeviceModel(Enum):
    iPhone3_1 = auto()


class OsBuildEnum(Enum):
    iPhone3_1_4_0_8A293 = auto()
    iPhone3_1_6_1_10B144 = auto()

    @property
    def unescaped_name(self):
        return TotalEnumMapping({
            OsBuildEnum.iPhone3_1_4_0_8A293: "iPhone3,1_4.0_8A293",
            OsBuildEnum.iPhone3_1_6_1_10B144: "iPhone3,1_6.1_10B144",
        })[self]

    @property
    def model(self) -> DeviceModel:
        return TotalEnumMapping({
            OsBuildEnum.iPhone3_1_4_0_8A293: DeviceModel.iPhone3_1,
            OsBuildEnum.iPhone3_1_6_1_10B144: DeviceModel.iPhone3_1,
        })[self]

    @property
    def ibss_subpath(self):
        return TotalEnumMapping({
            DeviceModel.iPhone3_1: Path("Firmware") / "dfu" / "iBSS.n90ap.RELEASE.dfu",
        })[self.model]

    @property
    def ibec_subpath(self):
        return TotalEnumMapping({
            DeviceModel.iPhone3_1: Path("Firmware") / "dfu" / "iBEC.n90ap.RELEASE.dfu",
        })[self.model]


class ImageType(Enum):
    iBSS = auto()
    iBEC = auto()


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

