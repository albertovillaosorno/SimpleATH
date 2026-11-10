#!/usr/bin/env python3
# Copyright (c) 2026 Alberto Villa Osorno.
"""Validate owner-authorized build tags using strict Mexico City CalVer."""

from datetime import datetime
import re
import sys
from zoneinfo import ZoneInfo

BUILD_PATTERN = re.compile(r"build-v[0-9]{4}\.[0-9]{4}\.[0-9]{4}\Z")
BUILD_FORMAT = "%Y.%m%d.%H%M"
BUILD_ZONE = ZoneInfo("America/Mexico_City")
EXPECTED_ARGV_COUNT = 2


def validate_tag(tag: str) -> bool:
    """Accept only actual calendar dates in build-vYYYY.MMDD.HHmm form.

    Returns:
        Whether the tag contains a well-formed Mexico City CalVer.

    """
    if BUILD_PATTERN.fullmatch(tag) is None:
        return False
    try:
        _ = datetime.strptime(tag[len("build-v") :], BUILD_FORMAT).replace(
            tzinfo=BUILD_ZONE
        )
    except ValueError:
        return False
    return True


def main() -> int:
    """Reject noncanonical build tags before native compilation.

    Returns:
        Zero only when the requested build tag is valid.

    """
    if len(sys.argv) != EXPECTED_ARGV_COUNT or not validate_tag(sys.argv[1]):
        sys.stderr.write("Build tag must be build-vYYYY.MMDD.HHmm\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
