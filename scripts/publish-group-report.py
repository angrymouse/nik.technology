#!/usr/bin/env python3
"""Copy the original HTML research report and its linked files without restyling."""

import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
from urllib.parse import unquote, urlsplit

from report_privacy import PublicationPrivacy


class Links(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.urls = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.urls.extend(value for key, value in attrs if key in ('href', 'src') and value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('research_directory', type=Path)
    parser.add_argument('--large-files-directory', type=Path, required=True)
    parser.add_argument('--release-tag', default='group-trading-research-2026-10-21')
    args = parser.parse_args()
    source = args.research_directory.resolve()
    site = Path(__file__).resolve().parents[1]
    destination = site / 'public/group-trading-is-minus-ev'
    destination.mkdir(parents=True, exist_ok=True)
    args.large_files_directory.mkdir(parents=True, exist_ok=True)
    queue = [source / 'latest_research_report.html']
    files = set()
    while queue:
        path = queue.pop()
        if path in files:
            continue
        if not path.is_relative_to(source) or not path.is_file():
            raise ValueError(f'Invalid report dependency: {path}')
        files.add(path)
        if path.suffix.lower() not in ('.html', '.htm'):
            continue
        for url in Links(path.read_text()).urls:
            parsed = urlsplit(url)
            if not parsed.scheme and not parsed.netloc and parsed.path:
                queue.append((path.parent / unquote(parsed.path)).resolve())

    privacy = PublicationPrivacy(source, files)
    manifest = {'sourceReport': 'latest_research_report.html', 'files': {}, 'largeFiles': {},
                'publicationRedaction': 'Direct Telegram identities and raw message text are removed from public copies.'}
    redirects = []
    for path in sorted(files):
        relative = path.relative_to(source).as_posix()
        content = privacy.transform(path, path.read_bytes())
        metadata = {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
        if len(content) > 25 * 1024 * 1024:
            asset_name = relative.replace('/', '--')
            url = f'https://github.com/angrymouse/nik.technology/releases/download/{args.release_tag}/{asset_name}'
            (args.large_files_directory / asset_name).write_bytes(content)
            manifest['largeFiles'][relative] = {**metadata, 'asset': asset_name, 'url': url}
            redirects.append(f'/group-trading-is-minus-ev/{relative} {url} 302')
        else:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
            manifest['files'][relative] = metadata

    keep = set(manifest['files']) | {'index.html', 'publication-manifest.json'}
    for stale in destination.rglob('*'):
        if stale.is_file() and stale.relative_to(destination).as_posix() not in keep:
            stale.unlink()
    for empty in sorted((path for path in destination.rglob('*') if path.is_dir()),
                        key=lambda path: len(path.parts), reverse=True):
        try:
            empty.rmdir()
        except OSError:
            pass
    shutil.copyfile(destination / 'latest_research_report.html', destination / 'index.html')
    manifest['files']['index.html'] = manifest['files']['latest_research_report.html']
    (destination / 'publication-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    start, end = '# BEGIN GROUP RESEARCH DOWNLOADS', '# END GROUP RESEARCH DOWNLOADS'
    redirect_path = site / 'public/_redirects'
    existing = redirect_path.read_text() if redirect_path.exists() else ''
    if start in existing:
        before, rest = existing.split(start, 1)
        _, after = rest.split(end, 1)
        existing = before + after.lstrip('\n')
    block = '\n'.join([start, *redirects, end]) + '\n'
    redirect_path.write_text(block + existing)
    print(json.dumps({'copiedFiles': len(manifest['files']), 'releaseAssets': manifest['largeFiles'],
                      'reportSha256': manifest['files']['index.html']['sha256']}, indent=2))


if __name__ == '__main__':
    main()
