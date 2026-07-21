from dataclasses import asdict, dataclass


@dataclass(frozen=True, slots=True)
class ChromeDownload:
    platform: str
    url: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class ChromeRelease:
    channel: str
    version: str
    revision: str
    downloads: tuple[ChromeDownload, ...]

    def get_download(self, platform: str) -> ChromeDownload:
        for download in self.downloads:
            if download.platform == platform:
                return download
        available = ", ".join(item.platform for item in self.downloads)
        raise KeyError(
            f"Chrome {self.channel} has no {platform} download; available: {available}"
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "browser_distribution": "chrome-for-testing",
            "channel": self.channel,
            "version": self.version,
            "revision": self.revision,
            "downloads": [item.to_dict() for item in self.downloads],
        }


@dataclass(frozen=True, slots=True)
class ConsumerChromeRelease:
    channel: str
    version: str
    platform: str

    def to_dict(self) -> dict[str, str]:
        return {
            "browser_distribution": "consumer-chrome",
            "channel": self.channel,
            "version": self.version,
            "platform": self.platform,
        }


@dataclass(frozen=True, slots=True)
class ProfileDifference:
    path: str
    before: object
    after: object

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CapabilityGap:
    path: str
    feature: str
    reason: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)
