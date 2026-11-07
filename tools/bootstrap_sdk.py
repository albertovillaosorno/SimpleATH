#!/usr/bin/env python3
"""Fetch only the pinned kernel SDK required for the SimpleATH Xcode target.

Linux ath9k code and Broadcom payloads are not linked into the v1 bootstrap.
"""
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parent.parent
DEST = ROOT / '.research' / 'MacKernelSDK'
URL = 'https://github.com/acidanthera/MacKernelSDK.git'
REVISION = '3f750085caa17ec3a7880f11c11bf4f48cd6a164'


def run(*args: str) -> None:
    subprocess.run(args, check=True)


def main() -> None:
    if not DEST.exists():
        DEST.parent.mkdir(exist_ok=True)
        run('git', 'clone', '--filter=blob:none', '--no-checkout', URL, str(DEST))
        run('git', '-C', str(DEST), 'sparse-checkout', 'set', 'Headers', 'Library/x86_64')
        run('git', '-C', str(DEST), 'checkout', '--detach', REVISION)
    actual = subprocess.check_output(
        ['git', '-C', str(DEST), 'rev-parse', 'HEAD'], text=True
    ).strip()
    if actual != REVISION:
        raise RuntimeError('MacKernelSDK is not at the pinned revision')
    if not (DEST / 'Headers/IOKit/IOService.h').is_file():
        raise RuntimeError('MacKernelSDK headers missing')
    if not (DEST / 'Library/x86_64').is_dir():
        raise RuntimeError('MacKernelSDK x86_64 libraries missing')
    print('MacKernelSDK verified:', actual)


if __name__ == '__main__':
    main()
