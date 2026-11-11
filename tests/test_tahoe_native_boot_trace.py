# Copyright (c) 2026 SimpleATH contributors.
"""Guard runtime boot checkpoints for the physical 1909 Tahoe freeze.

The owner-observed IO80211 initialization reached the kernel after successful
OpenCore injection, but the boot froze without a kernel backtrace. The native
runtime must log both sides of potentially blocking startup calls so a later
owner-provided verbose screen can isolate the unresolved phase. These checks
are source-only; they neither build nor load a kext.
"""

from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parent.parent
SOURCE = ROOT / "src/platform/tahoe/SimpleATHTahoeController.cpp"
HEADER = ROOT / "src/platform/tahoe/SimpleATHTahoeController.hpp"
CHECKPOINTS = (
    ("IO80211Init", "IO80211Controller::init(properties)"),
    ("ProviderBind", "transport_.bind(provider)"),
    ("WorkQueue", "createWorkQueue()"),
    ("CoreCapture", "capture_.start(this, workQueue_)"),
    ("IO80211Start", "IO80211Controller::start(provider)"),
    ("InfraInit", "infrastructure_->initialize(this)"),
    ("InfraAttach", "infrastructure_->attach(this)"),
    ("NativeAttach", "attachInterface(infrastructure_, this)"),
    ("InfraStart", "infrastructure_->start(this)"),
    ("InfraPublish", "infrastructure_->registerService()"),
)


class TahoeNativeBootTrace(unittest.TestCase):
    """Catch missing enter/ready pairs around the unknown runtime failure."""

    @staticmethod
    def test_superclass_init_override_preserves_native_base_call() -> None:
        header = HEADER.read_text(encoding="utf-8")
        source = SOURCE.read_text(encoding="utf-8")
        assert "bool init(OSDictionary *properties) override;" in header
        assert "bool SimpleATHTahoeController::init(" in source
        assert "if (!IO80211Controller::init(properties))" in source

    @staticmethod
    def test_every_potentially_blocking_startup_call_is_bracketed() -> None:
        source = SOURCE.read_text(encoding="utf-8")
        start_source = source.split("bool SimpleATHTahoeController::start(", 1)[
            1
        ].split("void SimpleATHTahoeController::stop(", 1)[0]
        for stage, call in CHECKPOINTS:
            region = source if stage == "IO80211Init" else start_source
            entered = f'IOLog("SimpleATH Tahoe: {stage}Enter\\n");'
            ready = f'IOLog("SimpleATH Tahoe: {stage}Ready\\n");'
            assert region.count(entered) == 1, f"{stage}: missing enter"
            assert region.count(ready) == 1, f"{stage}: missing ready"
            assert region.count(call) == 1, f"{stage}: unexpected call count"
            assert region.index(entered) < region.index(call), stage
            assert region.index(call) < region.index(ready), stage
            if stage != "InfraPublish":
                failed = f'IOLog("SimpleATH Tahoe: {stage}Failed\\n");'
                assert region.count(failed) == 1, f"{stage}: missing failure"
                assert region.index(call) < region.index(failed), stage
                assert region.index(failed) < region.index(ready), stage


if __name__ == "__main__":
    _ = unittest.main()
