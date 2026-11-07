# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Offline release-contract regressions; never run publishing entrypoints."""

from email.message import Message
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import sys
import tempfile
from unittest import TestCase
from unittest import mock
import urllib.response

# The legacy CLI has bare imports when executed from tools/ as a script.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
from build import CONFIGURATIONS
from build import package_name
from embed import VERSION

from tools import publish
from tools.publish import formal_release_from_event as formal_release
from tools.publish import read_json_response as decode_response
from tools.publish import require_json_array as sequence_response
from tools.publish import require_json_object as object_response
from tools.publish import require_release_id as github_id
from tools.publish import validate_https_url as https_url
from tools.publish import validate_identity
from tools.publish import verify_archives as archive_files

SHA = "a" * 40
OTHER = "b" * 40
REPOSITORY = "owner/SimpleATH"
SAMPLE = b"offline synthetic release asset"
EXPECTED_ID = 42
EXPECTED_JSON_ID = 12
EXPECTED_ASSET_COUNT = 2
ESCAPED_SUBJECT = r"\*\[probe\]\#tag\*"
IGNORED_SUBJECT = "ignored second line"
HTTPS_SERVER = "https://github.com"


def _rejects(action: object) -> bool:
    """Run only a supplied zero-argument test callback.

    Returns:
        True for ValueError or TypeError, never for unrelated failures.

    """
    if not callable(action):
        return False
    try:
        _ = action()
    except ValueError, TypeError:
        return True
    return False


class PublishContractTests(TestCase):
    """Pure release validation must reject malformed external metadata."""

    @staticmethod
    def test_invalid_json_shapes_and_ids_fail_closed() -> None:
        """Reject nonobjects, arrays, forged bool IDs and invalid SHA."""
        assert _rejects(lambda: object_response({1: "bad"}))
        assert _rejects(lambda: object_response([]))
        assert _rejects(lambda: sequence_response({}))
        assert _rejects(lambda: github_id(bool(EXPECTED_ID)))
        assert _rejects(lambda: github_id(0))
        assert github_id(EXPECTED_ID) == EXPECTED_ID
        assert _rejects(lambda: validate_identity("owner/name/extra", SHA))
        assert _rejects(lambda: validate_identity(REPOSITORY, "a" * 39))
        assert validate_identity(REPOSITORY, SHA) is None

    @staticmethod
    def test_https_server_url_refuses_credentials_and_fragment() -> None:
        """Do not generate Markdown or API requests with ambiguous URLs."""
        assert https_url(HTTPS_SERVER + "/", origin_only=True) == HTTPS_SERVER
        assert _rejects(
            lambda: https_url("file:///etc/passwd", origin_only=False)
        )
        assert _rejects(
            lambda: https_url("http://github.com", origin_only=True)
        )
        assert _rejects(
            lambda: https_url("https://user@github.com", origin_only=True)
        )
        assert _rejects(
            lambda: https_url("https://github.com/path", origin_only=True)
        )
        assert _rejects(
            lambda: https_url("https://github.com#bad", origin_only=False)
        )

    @staticmethod
    def test_release_note_commit_is_bounded_and_escaped() -> None:
        """Links require exact SHA and subjects cannot inject Markdown."""
        commit: dict[str, object] = {
            "sha": OTHER,
            "commit": {"message": "Fix *[probe]#tag*\nignored second line"},
        }
        with mock.patch.dict(
            os.environ, {"GITHUB_SHA": SHA, "GITHUB_SERVER_URL": HTTPS_SERVER}
        ):
            body = publish.prerelease_body(REPOSITORY, [commit])
            assert f"/blob/{SHA}/README.md" in body
            assert f"/commit/{OTHER}" in body
            assert ESCAPED_SUBJECT in body
            assert IGNORED_SUBJECT not in body
            bad = {"sha": "not-a-sha", "commit": {"message": "bad"}}
            assert _rejects(lambda: publish.prerelease_body(REPOSITORY, [bad]))

    @staticmethod
    def test_json_transport_is_structurally_checked() -> None:
        """Only HTTP-like response wrappers and valid JSON are accepted."""
        response = urllib.response.addinfourl(
            BytesIO(b'{"id": 12}'), Message(), HTTPS_SERVER
        )
        assert (
            object_response(decode_response(response))["id"] == EXPECTED_JSON_ID
        )
        assert _rejects(lambda: decode_response(BytesIO(b"{}")))
        malformed = urllib.response.addinfourl(
            BytesIO(b"{invalid"), Message(), HTTPS_SERVER
        )
        assert _rejects(lambda: decode_response(malformed))
        oversized = urllib.response.addinfourl(
            BytesIO(b"x" * (publish.MAX_RESPONSE_BYTES + 1)),
            Message(),
            HTTPS_SERVER,
        )
        assert _rejects(lambda: decode_response(oversized))

    @staticmethod
    def test_prebuilt_archive_checksum_is_required() -> None:
        """Reject checksum tampering without building binary artifacts."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dist = root / "dist"
            dist.mkdir()
            for configuration in CONFIGURATIONS:
                name = package_name(configuration, publish.CHANNEL_PRE, SHA)
                archive = dist / f"{name}.zip"
                _ = archive.write_bytes(SAMPLE)
                digest = hashlib.sha256(SAMPLE).hexdigest()
                _ = archive.with_name(archive.name + ".sha256").write_text(
                    f"{digest} {archive.name}\n", encoding="utf-8"
                )
            files = archive_files(root, publish.CHANNEL_PRE, SHA)
            assert len(files) == len(CONFIGURATIONS) * EXPECTED_ASSET_COUNT
            damaged = files[0]
            _ = damaged.write_bytes(b"changed")
            assert _rejects(
                lambda: archive_files(root, publish.CHANNEL_PRE, SHA)
            )

    @staticmethod
    def test_formal_event_rejects_wrong_tag_or_boolean_flags() -> None:
        """Only exact version tags and nondraft releases qualify."""
        with tempfile.TemporaryDirectory() as directory:
            event = Path(directory) / "event.json"
            payload: dict[str, object] = {
                "release": {
                    "tag_name": f"v{VERSION}",
                    "id": 123,
                    "prerelease": False,
                    "draft": False,
                }
            }
            _ = event.write_text(json.dumps(payload), encoding="utf-8")
            with mock.patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event)}):
                assert formal_release() == (f"v{VERSION}", 123)
                payload["release"] = {"tag_name": "unrelated", "id": 123}
                _ = event.write_text(json.dumps(payload), encoding="utf-8")
                assert _rejects(formal_release)
