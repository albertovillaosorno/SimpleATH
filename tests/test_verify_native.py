# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (c) 2026 SimpleATH contributors.
"""Fake-only forwarding ABI fixture tests; never invoke a Darwin compiler."""

import ast
from contextlib import ExitStack
from copy import deepcopy
import importlib
import json
import os
from pathlib import Path
import shutil
import subprocess  # ruff: ignore[suspicious-subprocess-import]
import sys
import tempfile
from types import SimpleNamespace
from typing import TYPE_CHECKING
from typing import TypeIs
from unittest import TestCase
from unittest import mock

from tools import native_forwarding_probe as probe
from tools.native_invariants import MAX_NATIVE_ARTIFACT_BYTES
from tools.native_invariants import read_native_artifact
from tools.native_invariants import reconstruct_payload_image
from tools.native_invariants import require

if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Mapping
    from types import ModuleType

FAKE_XCRUN = "/offline-fixture/xcrun"
ASSEMBLY = ".globl _athSkyForward0\n"
EXPECTED_CALLS = 12
EXPECT_FORWARD0 = 'extern "C" void athSkyForward0();'
EXPECT_CALLBACK1 = 'extern "C" void athSkyCallback1();'
EXPECT_FORWARD_PTR = "reinterpret_cast<uintptr_t>(athSkyForward1)"
EXPECTED_ABI_GUARDS = 52
SYNTHETIC_PAYLOAD_SIZE = 64
EXPECTED_RECONSTRUCTED_PAYLOAD = b"\x00ab\x00cd\x00"
REQUIRE_FUNCTION = "require"
RAW_READ_METHOD = "read_bytes"
CHECKED_READ_FUNCTION = "read_native_artifact"
RECONSTRUCT_FUNCTION = "reconstruct_payload_image"
ZIP_FUNCTION = "zip"
STRICT_ARGUMENT = "strict"
NATIVE_USER_CLIENT_SOURCE = "src/NativeUserClient.cpp"
STALE_USER_CLIENT_SOURCE = "SimpleATH/NativeUserClient.cpp"
MIN_BOUNDED_READS = 5
FAILURE_MARKER = "synthetic failed"
GOOD_OUTPUT = (
    '{"forwardingCalls":12,"retainedReceivers":4,"releasedReceivers":4}'
)


def _verifier_module() -> ModuleType:
    """Import the native verifier in package mode without starting a build.

    Returns:
        The pure Python verifier module for synthetic contract tests.

    """
    with mock.patch.object(
        sys,
        "path",
        [str(Path(__file__).parent.parent / "tools"), *sys.path],
    ):
        return importlib.import_module("tools.verify_native")


def _is_dict(value: object) -> TypeIs[dict[object, object]]:
    """Narrow the supported mutable mapping without unknown key types.

    Returns:
        Whether the value is an ordinary Python dictionary.

    """
    return isinstance(value, dict)


def _is_record(value: object) -> TypeIs[dict[str, object]]:
    """Recognize a mutable string-keyed synthetic JSON object.

    Returns:
        Whether the value can safely support checked field updates.

    """
    return _is_dict(value) and all(isinstance(key, str) for key in value)


def _is_list(value: object) -> TypeIs[list[object]]:
    """Recognize a synthetic JSON array without assuming element types.

    Returns:
        Whether positional indexing is valid on the supplied object.

    """
    return isinstance(value, list)


def _fixture_path(value: object, *path: str | int) -> object:
    """Resolve a typed path inside synthetic metadata without blind indexing.

    Returns:
        The value at the indicated dictionary key or list index.

    Raises:
        TypeError: The path shape no longer matches the synthetic fixture.

    """
    for key in path:
        if isinstance(key, str):
            if not _is_record(value):
                message = "Unexpected synthetic manifest object field"
                raise TypeError(message)
            value = value[key]
        elif _is_list(value):
            value = value[key]
        else:
            message = "Unexpected synthetic manifest array field"
            raise TypeError(message)
    return value


def _replace_fixture_path(
    source: dict[str, object], path: tuple[str | int, ...], value: object
) -> None:
    """Mutate only a verified nested test field, preserving source identity.

    Raises:
        TypeError: The fixture has an unexpected nested container shape.
        ValueError: The update path is empty.

    """
    if not path:
        message = "Missing synthetic manifest field path"
        raise ValueError(message)
    container = _fixture_path(source, *path[:-1])
    key = path[-1]
    if isinstance(key, str) and _is_record(container):
        container[key] = value
        return
    if isinstance(key, int) and _is_list(container):
        container[key] = value
        return
    message = "Unexpected synthetic manifest update container"
    raise TypeError(message)


def _load_manifest(source: bytes) -> object:
    """Call the isolated source verifier's checked manifest parser.

    Returns:
        Its structurally validated metadata, without compiling code.

    Raises:
        TypeError: The loaded verifier does not expose its parser.

    """
    exports: dict[str, object] = vars(_verifier_module())
    reader = exports.get("_read_manifest")
    if not callable(reader):
        message = "Source verifier manifest parser missing"
        raise TypeError(message)
    return reader(source)


def _verifier_type() -> type[object]:
    """Require the private verifier class from the isolated source module.

    Returns:
        The real verifier class, not a reimplemented test double.

    Raises:
        TypeError: The module does not expose the expected class.

    """
    exports: dict[str, object] = vars(_verifier_module())
    verifier_class = exports.get("_NativeVerifier")
    if not isinstance(verifier_class, type):
        message = "Source verifier class missing"
        raise TypeError(message)
    return verifier_class


def _fake_verifier_runner(plan: SimpleNamespace) -> object:
    """Allocate the real offline verifier without loading an external image.

    Returns:
        An uninitialized source verifier with synthetic typed plan state.

    """
    runner = object.__new__(_verifier_type())
    vars(runner)["plan"] = plan
    vars(runner)["checks"] = ["synthetic ABI contract"]
    return runner


def _run_patched_verifier(
    verifier_class: type[object],
    runner: object,
    ordered: tuple[str, ...],
    *,
    outputs: dict[str, object],
) -> tuple[object, list[tuple[str, tuple[object, ...]]]]:
    """Run the real verifier's stage order with synthetic byte-only stages.

    Returns:
        The actual run report and observed stage arguments.

    Raises:
        TypeError: A source verifier is missing its callable run method.

    """
    visited: list[tuple[str, tuple[object, ...]]] = []
    with ExitStack() as patches:
        for name in ordered:

            def stub(*args: object, stage: str = name) -> object:
                visited.append((stage, args[1:]))
                return outputs.get(stage)

            _ = patches.enter_context(
                mock.patch.object(verifier_class, name, new=stub)
            )
        methods: Mapping[str, object] = vars(verifier_class)
        run = methods.get("run")
        if not callable(run):
            message = "Source verifier run method missing"
            raise TypeError(message)
        report: object = run(runner)
    return report, visited


def _manifest_fixture() -> dict[str, object]:
    """Create a complete small native verification metadata fixture.

    Returns:
        A source-only manifest with every required field populated.

    """
    return {
        "payloads": [
            {
                "label": "Legacy",
                "size": SYNTHETIC_PAYLOAD_SIZE,
                "namespacedClassStrings": {"IO80211Controller": [4, 12]},
                "powerDomainPatches": [],
            }
        ],
        "nativeAdapter": {
            "wirelessControllerIdentity": "AirPortDriver",
            "powerDomain": {
                "strategy": "pci-provider",
                "airPortTablePreserved": True,
            },
        },
        "systemProfiles": [
            {
                "system": "Tahoe",
                "nativeUUID": "synthetic-native",
                "wirelessUUID": "synthetic-wireless",
                "ethernetSize": 232,
                "poolSize": 304,
                "ethernetLinkSlot": 9,
                "airPortPayloadIndex": 2,
            }
        ],
        "nativeRuntimeGuards": {
            "Tahoe": {
                "classes": [["__ZN4Mock10gMetaClassE", 224]],
                "vtables": [["Mock", 8, "_method"]],
            }
        },
    }


def _reject(
    action: Callable[[], object],
    errors: tuple[type[Exception], ...] = (ValueError, OSError),
) -> bool:
    try:
        _ = action()
    except errors:
        return True
    return False


class NativeVerifierManifestTests(TestCase):
    """Reject malformed generated payload metadata before reading artifacts."""

    @staticmethod
    def test_parse_typed_complete_metadata() -> None:
        """Keep exact source fields and preserve the nested output shape."""
        document = _load_manifest(
            json.dumps(_manifest_fixture()).encode("utf-8")
        )
        assert _fixture_path(document, "payloads", 0, "size") == (
            SYNTHETIC_PAYLOAD_SIZE
        )
        assert _fixture_path(
            document, "payloads", 0, "namespacedClassStrings"
        ) == {"IO80211Controller": [4, 12]}
        assert (
            _fixture_path(
                document,
                "nativeAdapter",
                "powerDomain",
                "airPortTablePreserved",
            )
            is True
        )
        assert _fixture_path(
            document, "nativeRuntimeGuards", "Tahoe", "classes"
        ) == [("__ZN4Mock10gMetaClassE", 224)]

    def test_reject_malformed_payload_and_runtime_metadata(self) -> None:
        """Require exact integer, array, mapping and class pair shapes."""
        valid = _manifest_fixture()
        bad_values: tuple[tuple[str, object], ...] = (
            ("size", True),
            ("size", "64"),
            ("namespacedClassStrings", {"IO80211Controller": [False]}),
            ("powerDomainPatches", "missing"),
        )
        for field, value in bad_values:
            with self.subTest(field=field, value=str(value)):
                source = deepcopy(valid)
                _replace_fixture_path(source, ("payloads", 0, field), value)
                assert _reject(
                    lambda current=source: _load_manifest(
                        json.dumps(current).encode("utf-8")
                    ),
                    (TypeError, ValueError),
                )

        invalid_runtime = deepcopy(valid)
        _replace_fixture_path(
            invalid_runtime,
            ("nativeRuntimeGuards", "Tahoe", "classes"),
            [["__ZN4Mock10gMetaClassE", 224, 999]],
        )
        assert _reject(
            lambda: _load_manifest(json.dumps(invalid_runtime).encode("utf-8"))
        )

    @staticmethod
    def test_reject_nonboolean_adapter_and_invalid_root() -> None:
        """Reject truthy impostors and non-object JSON manifests."""
        source = _manifest_fixture()
        _replace_fixture_path(
            source,
            ("nativeAdapter", "powerDomain", "airPortTablePreserved"),
            "true",
        )
        assert _reject(
            lambda: _load_manifest(json.dumps(source).encode("utf-8")),
            (TypeError,),
        )
        assert _reject(lambda: _load_manifest(b"[]"))


class NativeForwardingProbeTests(TestCase):
    """Keep template generation deterministic and compiler dispatch opt-in."""

    @staticmethod
    def test_checked_template_replaces_every_exact_placeholder() -> None:
        """Render two methods with their expected forwarding symbols."""
        source = probe.render_fixture(2)
        assert EXPECT_FORWARD0 in source
        assert EXPECT_CALLBACK1 in source
        assert EXPECT_FORWARD_PTR in source
        for token in (probe.DECLARATIONS, probe.FORWARDERS, probe.CALLBACKS):
            assert token not in source

    @staticmethod
    def test_missing_duplicate_or_changed_template_rejects() -> None:
        """Never silently compile partial fixture placeholders."""
        with mock.patch.object(
            Path, "read_text", return_value="bad @FORWARDERS@"
        ):
            assert _reject(lambda: probe.render_fixture(2))
        with mock.patch.object(
            Path,
            "read_text",
            return_value="@DECLARATIONS@@DECLARATIONS@@FORWARDERS@@CALLBACKS@",
        ):
            assert _reject(lambda: probe.render_fixture(2))
        for count in (0, -1, probe.MAX_FORWARDERS + 1):
            assert _reject(lambda count=count: probe.render_fixture(count))

    @staticmethod
    def test_missing_toolchain_never_launches_or_writes() -> None:
        """A missing local macOS tool is not misreported as a pass."""
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(shutil, "which", return_value=None),
            mock.patch.object(subprocess, "run") as launch,
            mock.patch.object(subprocess, "check_output") as executable,
        ):
            root = Path(directory)
            assert _reject(lambda: probe.run_probe(root, ASSEMBLY, 2))
            assert list(root.iterdir()) == []
            launch.assert_not_called()
            executable.assert_not_called()

    @staticmethod
    def test_compiler_dispatch_is_fixed_and_bounded() -> None:
        """Check fixed argv and bounded timeouts without a shell."""
        with (
            tempfile.TemporaryDirectory() as directory,
            mock.patch.object(shutil, "which", return_value=FAKE_XCRUN),
            mock.patch.object(subprocess, "run") as launch,
            mock.patch.object(
                subprocess, "check_output", return_value=GOOD_OUTPUT
            ) as executable,
        ):
            root = Path(directory)
            assert (
                probe.run_probe(root, ASSEMBLY, 2)["forwardingCalls"]
                == EXPECTED_CALLS
            )
            assert (root / "Forwarding.S").read_text() == (
                ".section __TEXT,__text\n" + ASSEMBLY
            )
            assert (root / "ForwardingValidation.cpp").read_text() == (
                probe.render_fixture(2)
            )
            launch.assert_called_once_with(
                [
                    FAKE_XCRUN,
                    "clang++",
                    "-std=c++14",
                    "-O1",
                    "-UNDEBUG",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                    str(root / "ForwardingValidation.cpp"),
                    str(root / "Forwarding.S"),
                    "-o",
                    str(root / "forwarding"),
                ],
                check=True,
                shell=False,
                timeout=120,
            )
            executable.assert_called_once_with(
                [str(root / "forwarding")],
                text=True,
                shell=False,
                timeout=60,
            )

    @staticmethod
    def test_malformed_or_inconsistent_reports_fail_closed() -> None:
        """Reject missing calls, bogus JSON, boolean counts and leaked refs."""
        for output in (
            "[]",
            "{",
            "{}",
            '{"forwardingCalls":true,"retainedReceivers":4,"releasedReceivers":4}',
            '{"forwardingCalls":11,"retainedReceivers":4,"releasedReceivers":4}',
            '{"forwardingCalls":12,"retainedReceivers":4,"releasedReceivers":3}',
            '{"forwardingCalls":12,"retainedReceivers":3,"releasedReceivers":3}',
        ):
            assert _reject(
                lambda output=output: probe.checked_counts(output, 2)
            )
        assert probe.checked_counts(GOOD_OUTPUT, 2) == {
            "forwardingCalls": 12,
            "retainedReceivers": 4,
            "releasedReceivers": 4,
        }

    @staticmethod
    def test_missing_folder_or_source_rejects_prelaunch() -> None:
        """Reject absent assembly/folder and excessive method bounds early."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            assert _reject(
                lambda: probe.run_probe(root / "absent", ASSEMBLY, 2)
            )
            assert _reject(lambda: probe.run_probe(root, "", 2))
            assert _reject(
                lambda: probe.run_probe(
                    root, ASSEMBLY, probe.MAX_FORWARDERS + 1
                )
            )


class NativeAbiInvariantTests(TestCase):
    """Prevent Python optimization from silently disabling ABI validation."""

    @staticmethod
    def test_all_verifier_asserts_are_explicit_guards() -> None:
        """Keep every native verification check active under Python -O."""
        source = Path(__file__).parent.parent / "tools/verify_native.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        assert not any(isinstance(node, ast.Assert) for node in ast.walk(tree))
        guards = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == REQUIRE_FUNCTION
        ]
        assert len(guards) == EXPECTED_ABI_GUARDS

    @staticmethod
    def test_all_generated_binary_reads_have_bounded_preflight() -> None:
        """Keep generated payload reads on the nofollow artifact boundary."""
        source = Path(__file__).parent.parent / "tools/verify_native.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        calls = [
            node.func for node in ast.walk(tree) if isinstance(node, ast.Call)
        ]
        assert not any(
            isinstance(callee, ast.Attribute) and callee.attr == RAW_READ_METHOD
            for callee in calls
        )
        assert (
            sum(
                isinstance(callee, ast.Name)
                and callee.id == CHECKED_READ_FUNCTION
                for callee in calls
            )
            >= MIN_BOUNDED_READS
        )
        assert any(
            isinstance(callee, ast.Name) and callee.id == RECONSTRUCT_FUNCTION
            for callee in calls
        )

    @staticmethod
    def test_verifier_reads_current_source_and_checks_all_client_tables() -> (
        None
    ):
        """Fail closed on truncated tables and avoid the obsolete path."""
        root = Path(__file__).parent.parent
        source = root / "tools/verify_native.py"
        tree = ast.parse(source.read_text(encoding="utf-8"))
        literals = {
            node.value
            for node in ast.walk(tree)
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        }
        assert NATIVE_USER_CLIENT_SOURCE in literals
        assert STALE_USER_CLIENT_SOURCE not in literals
        assert (root / NATIVE_USER_CLIENT_SOURCE).is_file()
        zips = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == ZIP_FUNCTION
        ]
        assert zips
        assert all(
            any(
                kw.arg == STRICT_ARGUMENT
                and isinstance(kw.value, ast.Constant)
                and kw.value.value is True
                for kw in call.keywords
            )
            for call in zips
        )

    @staticmethod
    def test_reference_only_image_cannot_reach_forwarding_probe() -> None:
        """Reject a metadata-only image before launching a host ABI probe.

        Raises:
            TypeError: The source verifier has no callable forwarding stage.

        """
        verifier = _verifier_module()
        verifier_class = _verifier_type()
        runner = _fake_verifier_runner(SimpleNamespace(old=object()))
        attributes: Mapping[str, object] = vars(verifier_class)
        forwarding_stage = attributes.get("_check_forwarding")
        if not callable(forwarding_stage):
            message = "Source forwarding verifier stage missing"
            raise TypeError(message)

        def invoke() -> object:
            """Run the exact unbound verifier method on a fake source owner.

            Returns:
                The offline stage result if it unexpectedly succeeds.

            """
            return forwarding_stage(runner)

        with mock.patch.object(verifier, "run_probe") as launch:
            assert _reject(invoke, (TypeError,))
            launch.assert_not_called()

    @staticmethod
    def test_verifier_stages_keep_ordered_fail_closed_execution() -> None:
        """Preserve stages, output shape and offline resource teardown."""
        wireless_close = mock.Mock()
        model_close = mock.Mock()
        runner = _fake_verifier_runner(
            SimpleNamespace(
                packet_calls=[1, 2],
                vptr_sites=[1],
                pool_meta=[1, 2, 3],
                callbacks=[("native", "legacy", [1, 2])],
                wireless=SimpleNamespace(close=wireless_close),
                model=SimpleNamespace(close=model_close),
            )
        )
        ordered = (
            "_check_payloads",
            "_check_profile",
            "_check_controller",
            "_check_power",
            "_check_facade",
            "_check_clients",
            "_check_callbacks",
            "_check_packet_calls",
            "_check_constructors",
            "_check_forwarding",
        )
        legacy = b"synthetic old source"
        product = object()
        evidence = {"forwardingCalls": 6}
        outputs: dict[str, object] = {
            "_check_payloads": legacy,
            "_check_facade": product,
            "_check_forwarding": evidence,
        }
        report, visited = _run_patched_verifier(
            _verifier_type(), runner, ordered, outputs=outputs
        )
        assert tuple(name for name, _ in visited) == ordered
        assert visited[2][1] == (legacy,)
        assert visited[5][1] == (product,)
        assert report == {
            "checks": ["synthetic ABI contract"],
            "forwarding": evidence,
            "packetCallSites": 2,
            "packetConstructors": 1,
            "poolSizeSites": 3,
            "nativeInterfaceCallbacks": [2],
            "kernelExecution": False,
            "hardwareValidation": "not-run-by-build",
        }
        wireless_close.assert_called_once_with()
        model_close.assert_called_once_with()

    @staticmethod
    def test_invariant_guard_rejects_false_or_nonboolean_truthy() -> None:
        """Reject false checks and malformed truthy manifest metadata."""
        verified = True
        assert require(verified, "synthetic verified") is None
        invalid: tuple[object, ...] = (
            False,
            None,
            1,
            "true",
            [0],
            {"fake": True},
            0,
        )
        errors: list[str] = []
        for condition in invalid:
            try:
                require(condition, FAILURE_MARKER)
            except ValueError as error:
                errors.append(str(error))
            else:
                errors.append("Accepted malformed native ABI condition")
        assert len(errors) == len(invalid)
        assert all(FAILURE_MARKER in error for error in errors)


class NativePayloadReconstructionTests(TestCase):
    """Rebuild binary regions only after bounded segment validation."""

    @staticmethod
    def test_in_bounds_segments_reconstruct_with_zero_gaps() -> None:
        """Preserve file bytes and zero-fill gaps in an exact-length image."""
        payload = reconstruct_payload_image(
            7, [(1, 0, 2), (4, 3, 2)], b"Xab0cd", base=1
        )
        assert payload == EXPECTED_RECONSTRUCTED_PAYLOAD

    @staticmethod
    def test_invalid_manifest_sizes_rejected_before_allocation() -> None:
        """Reject bool, missing, zero, negative, and oversized dimensions."""
        values: tuple[object, ...] = (
            None,
            True,
            "4",
            0,
            -1,
            MAX_NATIVE_ARTIFACT_BYTES + 1,
        )
        for size in values:
            assert _reject(
                lambda size=size: reconstruct_payload_image(size, [], b"abcd")
            )

    @staticmethod
    def test_source_and_target_span_errors_are_fatal() -> None:
        """Reject underflow, length overflow, truncated data and bad bases."""
        bad_segments = (
            (-1, 0, 1),
            (0, -1, 1),
            (0, 0, -1),
            (6, 0, 1),
            (0, 4, 1),
            (5, 0, 2),
        )
        for segment in bad_segments:
            assert _reject(
                lambda segment=segment: reconstruct_payload_image(
                    6, [segment], b"abcd"
                )
            )
        assert _reject(
            lambda: reconstruct_payload_image(6, [], b"abcd", base=-1)
        )
        assert _reject(
            lambda: reconstruct_payload_image(6, [], b"abcd", base=5)
        )
        assert _reject(
            lambda: reconstruct_payload_image(6, [(0, -1, 1)], b"abcd", base=2)
        )


class NativeArtifactReadTests(TestCase):
    """Artifact verification refuses unsafe disk input before binary checks."""

    @staticmethod
    def test_regular_product_is_read_exactly() -> None:
        """Preserve all bytes of a synthetic native product."""
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory) / "product.bin"
            source = b"\x00\x01\xfe\xffnative"
            _ = product.write_bytes(source)
            assert read_native_artifact(product) == source

    @staticmethod
    def test_symlink_fifo_and_empty_source_are_refused() -> None:
        """Never follow a link or block on a named pipe."""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "real.bin"
            _ = source.write_bytes(b"real")
            (root / "link.bin").symlink_to(source)
            fifo = root / "fifo.bin"
            os.mkfifo(fifo)
            empty = root / "empty.bin"
            _ = empty.write_bytes(b"")
            for path in (root / "link.bin", fifo, empty):
                assert _reject(lambda path=path: read_native_artifact(path))

    @staticmethod
    def test_oversize_sparse_artifact_is_refused_without_reading() -> None:
        """Reject a huge synthetic artifact from its metadata alone."""
        with tempfile.TemporaryDirectory() as directory:
            product = Path(directory) / "oversized.bin"
            _ = product.write_bytes(b"a")
            os.truncate(product, MAX_NATIVE_ARTIFACT_BYTES + 1)
            assert _reject(lambda: read_native_artifact(product))
