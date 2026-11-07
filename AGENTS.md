# SimpleATH agent onboarding

Follow the exact 4,000-character implementation assignment in:

`docs/agents/COMPLETE_SIMPLEATH_PROMPT.txt`

The task is to develop and validate a **real** AR9565 Wi-Fi driver for
macOS Tahoe, not to present a dummy kext as functional Wi-Fi. Read the
existing code, bring-up record, relevant Linux references, and commit history
before making changes. Preserve the current architecture unless a specific
problem requires a documented improvement.

## Authorization boundary

As of this instruction the owner has **not authorized another build**.
Do not compile or generate a kernel extension, create or push any build-v*
tag, trigger GitHub Actions, run test suites, modify OpenCore/EFI/USB/SSD,
install drivers, or conduct real-hardware experiments without new explicit
permission. Source edits, static inspection, documentation and ordinary
commits/pushes to main are permitted. Ordinary pushes do not start CI.

## Engineering and licensing

Keep user-facing messages in the user's preferred language but write source
comments and technical documentation in English. New code is AGPL-3.0-only;
Linux-derived data must preserve its upstream permissive notices and
file-specific licensing. The only third-party notices are Linux and
SimpleBCM. Never claim that the Wi-Fi functionality is complete until it
actually passes wireless networking acceptance tests on the Dell.
