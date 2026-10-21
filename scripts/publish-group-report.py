#!/usr/bin/env python3
"""Copy the original HTML research report and its linked files without restyling."""

import argparse
import hashlib
from html.parser import HTMLParser
import json
from pathlib import Path
import shutil
from urllib.parse import unquote, urlsplit


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

    manifest = {'sourceReport': 'latest_research_report.html', 'files': {}, 'largeFiles': {}}
    redirects = []
    for path in sorted(files):
        relative = path.relative_to(source).as_posix()
        content = path.read_bytes()
        metadata = {'bytes': len(content), 'sha256': hashlib.sha256(content).hexdigest()}
        if len(content) > 25 * 1024 * 1024:
            asset_name = relative.replace('/', '--')
            url = f'https://github.com/angrymouse/nik.technology/releases/download/{args.release_tag}/{asset_name}'
            shutil.copyfile(path, args.large_files_directory / asset_name)
            manifest['largeFiles'][relative] = {**metadata, 'asset': asset_name, 'url': url}
            redirects.append(f'/group-trading-is-minus-ev/{relative} {url} 302')
        else:
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, target)
            manifest['files'][relative] = metadata

    shutil.copyfile(source / 'latest_research_report.html', destination / 'index.html')
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
