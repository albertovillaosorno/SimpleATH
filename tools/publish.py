#!/usr/bin/env python3
#
#  publish.py
#  SimpleATH
#
#  Created by laobamac on 2026/9/28.
#  Copyright © 2026 laobamac. All rights reserved.
#

import argparse
import hashlib
import json
import os
import re
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

from build import CONFIGURATIONS, VERSION, package_name


def prerelease_body(repository, commits):
    repository_url = os.environ.get('GITHUB_SERVER_URL', 'https://github.com') + '/' + repository
    changes = []
    for commit in commits:
        subject = commit['commit']['message'].splitlines()[0]
        subject = re.sub(r'([\\`*_{}\[\]<>#|])', r'\\\1', subject)
        changes.append(f'- [`{commit["sha"][:7]}`]({repository_url}/commit/{commit["sha"]}) {subject}')
    return ('Experimental SimpleATH kernel bootstrap build (no active Wi-Fi backend).\n\n'
            'Stage 1 deliberately omits the original Broadcom payload and Skywalk bridge.\n'
            f'Installation: [README]({repository_url}/blob/{os.environ["GITHUB_SHA"]}/README.en.md).\n\n' +
            '\n'.join(changes) + '\n')


def release_body():
    # Historical upstream Broadcom release template, retained for reference.
    # The current SimpleATH bootstrap does not implement a Wi-Fi backend.
    return """The original SimpleBCM architecture supports macOS Sonoma, Sequoia, and Tahoe
    with native Skywalk using OpenCore injection, without modifying the system volume.

- The original Broadcom implementation embeds a Legacy payload and two AirPort
  backends. It registers only the Legacy payload and the backend selected for
  the running macOS version. Old Skywalk code is not embedded.
- Remove or disable IOSkywalkFamily Block/Exclude rules when using that original
  Broadcom implementation. Keep native IOSkywalkFamily and IO80211Family enabled.
  Disable separately injected legacy drivers and use the original configuration
  fragment.
- The original implementation targets x86_64 Sonoma 14, Sequoia 15, and
  Tahoe 26, without restricting minor OS versions.
- The original project provides DEBUG and RELEASE packages; choose RELEASE for
  everyday use. AirportBrcmFixup must be supplied separately if needed.

**SimpleATH status:** Experimental minimal kernel bootstrap only. It does not
implement Broadcom or Atheros Wi-Fi connectivity. This upstream release template
is retained for development reference; the tag-only SimpleATH CI workflow does
not run this publishing script.
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--channel', choices=('pre', 'rel'), required=True)
    parser.add_argument('--dry-run', action='store_true')
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    repository = os.environ['GITHUB_REPOSITORY']
    sha = os.environ['GITHUB_SHA'].lower()
    if not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', repository):
        raise SystemExit('Invalid repository name')
    if not re.fullmatch(r'[0-9a-fA-F]{40}', sha):
        raise SystemExit('Invalid commit SHA')
    body = release_body() if args.channel == 'rel' else None
    files = []
    for configuration in CONFIGURATIONS:
        name = package_name(configuration, args.channel, sha)
        archive = root / 'dist' / (name + '.zip')
        checksum = archive.with_name(archive.name + '.sha256')
        if not archive.is_file() or not checksum.is_file():
            raise SystemExit(f'Release archive or checksum is missing: {name}')
        if checksum.read_text().split() != [hashlib.sha256(archive.read_bytes()).hexdigest(), archive.name]:
            raise SystemExit(f'Release archive checksum differs: {name}')
        files.extend((archive, checksum))
    release = None
    if args.channel == 'rel':
        release = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text()).get('release', {})
        tag = release.get('tag_name', '')
        if release.get('prerelease') or release.get('draft') or tag not in (VERSION, f'v{VERSION}'):
            raise SystemExit(f'Formal release tag must be {VERSION} or v{VERSION}')
    else:
        tag = f'v{VERSION}-alpha'
    if args.dry_run:
        print(json.dumps({'repository': repository, 'tag': tag, 'channel': args.channel,
                          'body': body, 'assets': [p.name for p in files]}, indent=2))
        return
    token = os.environ['GH_TOKEN']
    api = os.environ.get('GITHUB_API_URL', 'https://api.github.com')
    base = f'/repos/{repository}'

    def request(method, path, data=None, missing=False):
        body = None if data is None else json.dumps(data).encode()
        headers = {'Accept': 'application/vnd.github+json', 'Authorization': f'Bearer {token}',
                   'X-GitHub-Api-Version': '2022-11-28', 'Content-Type': 'application/json'}
        query = urllib.request.Request(api + path, data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(query, timeout=60) as response:
                text = response.read()
                return json.loads(text) if text else None
        except urllib.error.HTTPError as error:
            if error.code == 404 and missing:
                return None
            raise SystemExit(f'GitHub {method} {path} failed: HTTP {error.code}') from None

    if release is not None:
        current = request('GET', base + '/releases/' + str(release['id']))
        if current['tag_name'] != tag or current['prerelease'] or current['draft']:
            raise SystemExit('Release state changed during the build')
        request('PATCH', base + '/releases/' + str(current['id']), {'body': body})
    else:
        encoded = urllib.parse.quote(tag, safe='')
        current = request('GET', base + '/releases/tags/' + encoded, missing=True)
        if current and (not current['prerelease'] or current['draft']):
            raise SystemExit('Alpha tag is already used by a formal or draft release')
        ref = request('GET', base + '/git/ref/tags/' + encoded, missing=True)
        if ref:
            request('PATCH', base + '/git/refs/tags/' + encoded, {'sha': sha, 'force': True})
        else:
            request('POST', base + '/git/refs', {'ref': 'refs/tags/' + tag, 'sha': sha})
        commits = request('GET', base + f'/commits?sha={sha}&per_page=5')
        body = prerelease_body(repository, commits)
        values = {'tag_name': tag, 'target_commitish': sha, 'name': tag, 'body': body,
                  'draft': False, 'prerelease': True, 'make_latest': 'false'}
        if current:
            current = request('PATCH', base + '/releases/' + str(current['id']), values)
        else:
            current = request('POST', base + '/releases', values)
    subprocess.run(['gh', 'release', 'upload', tag, *(str(p) for p in files), '--repo', repository, '--clobber'], check=True)
    if args.channel == 'pre':
        keep = {p.name for p in files}
        page = 1
        stale = []
        while True:
            assets = request('GET', base + f'/releases/{current["id"]}/assets?per_page=100&page={page}')
            stale.extend(asset['id'] for asset in assets if asset['name'] not in keep)
            if len(assets) < 100:
                break
            page += 1
        for identifier in stale:
            request('DELETE', base + '/releases/assets/' + str(identifier))
        page = 1
        stale_releases = []
        while True:
            releases = request('GET', base + f'/releases?per_page=100&page={page}')
            stale_releases.extend(item['id'] for item in releases
                                  if item['prerelease'] and not item['draft'] and item['id'] != current['id'])
            if len(releases) < 100:
                break
            page += 1
        for identifier in stale_releases:
            request('DELETE', base + '/releases/' + str(identifier))
    print(f'Published {tag}: ' + ', '.join(p.name for p in files))


if __name__ == '__main__':
    main()
