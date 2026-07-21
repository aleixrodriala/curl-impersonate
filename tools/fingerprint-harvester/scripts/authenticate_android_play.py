#!/usr/bin/env python3
"""Cache anonymous Google Play authentication for a requested architecture."""

import argparse

from fingerprint_harvester.android_play import (
    SUPPORTED_ARCHITECTURES,
    authenticate_play,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--arch", choices=SUPPORTED_ARCHITECTURES, required=True)
    parser.add_argument("--dispenser")
    args = parser.parse_args()

    authenticate_play(args.arch, args.dispenser)
    print(f"Cached anonymous Google Play authentication for {args.arch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
