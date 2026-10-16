"""Temporary artifact verifier and in-process pytest ANGLE identity probe.

The fixed hashes identify the x64 DLLs built by baseline run 38953844827.
The CLI needs only the standard library; pytest loads this file as a plugin.
"""

import argparse
import ctypes
from ctypes import wintypes
from email.parser import Parser
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import re
import sys
from urllib.parse import urlparse
from urllib.request import url2pathname
import zipfile


BASELINE = {
    'repository': 'AndreMiras/kivy-sdk-packager',
    'run_id': 38953844827,
    'commit': 'ac16dfc4bf262a33611c1a62801fe6a504105d89',
    'native_artifact_id': 12075486413,
}
DLL_HASHES = {
    'd3dcompiler_47.dll':
        'a05f99734f7c4822fefc12b367af21fd0976ed6608752fb1e1e80b6ece7ecbbb',
    'libEGL.dll':
        'dc1d2f73e986f5d4a3863ce7cc2dc8f6c54eb9c27ffeddbf202fa3b876c92562',
    'libGLESv2.dll':
        '74e330560308882a5e093f761b6afcfba93a39b535bf2a55ef1b0612dfb3aaf6',
}
# The shader compiler can be lazy-loaded. Its installed hash is always checked;
# if it is loaded, its path/hash must match too. EGL/GLES must be witnessed.
REQUIRED_MODULES = {'libegl.dll', 'libglesv2.dll'}


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def canonical_path(path):
    return os.path.normcase(os.path.realpath(path))


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def prepare(profile, native_dir, wheel_dir, manifest_path):
    for name, expected in DLL_HASHES.items():
        path = native_dir / name
        require(sha256(path) == expected,
                'Baseline native DLL hash mismatch: {}'.format(path))

    python_tag = 'cp{}{}'.format(*sys.version_info[:2])
    wheels = []
    for suffix, distribution in (
        ('', 'kivy-deps-angle'), ('_dev', 'kivy-deps-angle-dev')
    ):
        filename = 'kivy_deps_angle{}-0.5.0-{}-{}-win_amd64.whl'.format(
            suffix, python_tag, python_tag)
        path = (wheel_dir / filename).resolve(strict=True)
        with zipfile.ZipFile(path) as archive:
            names = archive.namelist()
            info_names = [name for name in names
                          if name.endswith('.dist-info/METADATA')]
            require(len(info_names) == 1, 'Expected one wheel METADATA file')
            info = Parser().parsestr(archive.read(info_names[0]).decode('utf8'))
            normalized = re.sub(r'[-_.]+', '-', info['Name']).lower()
            require(normalized == distribution and info['Version'] == '0.5.0',
                    'Unexpected distribution metadata in {}'.format(path))
            dlls = [name for name in names if name.lower().endswith('.dll')]
            expected_names = [] if suffix else list(DLL_HASHES)
            require(sorted(Path(name).name for name in dlls)
                    == sorted(expected_names),
                    'Unexpected DLL set in {}'.format(path))
            for member in dlls:
                name = Path(member).name
                require('/data/share/angle/bin/' in member,
                        'Unexpected wheel DLL destination: {}'.format(member))
                digest = hashlib.sha256(archive.read(member)).hexdigest()
                require(digest == DLL_HASHES[name],
                        'Wheel/native DLL mismatch: {}'.format(member))
        wheels.append({'distribution': distribution, 'path': str(path),
                       'sha256': sha256(path)})

    manifest = {
        'baseline': BASELINE, 'python': python_tag, 'profile': profile,
        'backend': 'angle_sdl2' if profile == 'stable' else 'angle_sdl3',
        'dlls': DLL_HASHES, 'wheels': wheels,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2) + '\n',
                             encoding='utf8')
    print('ANGLE_DIAGNOSTIC ' + json.dumps(
        {'event': 'prepared', 'manifest': manifest}), flush=True)


def verify_installed(manifest):
    records = []
    for wheel in manifest['wheels']:
        distribution = metadata.distribution(wheel['distribution'])
        require(distribution.version == '0.5.0',
                'Unexpected installed version: {}'.format(wheel['distribution']))
        direct_url = json.loads(distribution.read_text('direct_url.json') or '{}')
        url = urlparse(direct_url.get('url', ''))
        require(url.scheme == 'file' and not url.netloc,
                'Installed distribution is not from a local wheel: {}'.format(
                    wheel['distribution']))
        origin = url2pathname(url.path)
        require(canonical_path(origin) == canonical_path(wheel['path']),
                'Installed wheel origin mismatch: {}'.format(origin))
        archive_info = direct_url.get('archive_info', {})
        digest = archive_info.get('hashes', {}).get('sha256')
        if digest is None:
            digest = archive_info.get('hash', '').removeprefix('sha256=')
        require(digest == wheel['sha256'],
                'Installed wheel archive hash mismatch: {}'.format(origin))
        records.append({'distribution': wheel['distribution'],
                        'version': distribution.version, 'direct_url': direct_url})

    directory = Path(sys.prefix) / 'share' / 'angle' / 'bin'
    for name, expected in manifest['dlls'].items():
        path = directory / name
        digest = sha256(path)
        require(digest == expected,
                'Installed DLL hash mismatch: {}'.format(path))
        records.append({'path': str(path), 'sha256': digest})
    return records


def module_paths():
    """Enumerate actual modules without loading any ANGLE DLL for the probe."""
    require(sys.platform == 'win32', 'Loaded DLL inspection requires Windows')
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    psapi = ctypes.WinDLL('psapi', use_last_error=True)
    kernel32.GetCurrentProcess.argtypes = []
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.GetModuleFileNameW.argtypes = [
        wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.GetModuleFileNameW.restype = wintypes.DWORD
    psapi.EnumProcessModules.argtypes = [
        wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE), wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD)]
    psapi.EnumProcessModules.restype = wintypes.BOOL
    process = kernel32.GetCurrentProcess()
    capacity = 1024
    while True:
        modules = (wintypes.HMODULE * capacity)()
        needed = wintypes.DWORD()
        if not psapi.EnumProcessModules(process, modules, ctypes.sizeof(modules),
                                        ctypes.byref(needed)):
            raise ctypes.WinError(ctypes.get_last_error())
        if needed.value <= ctypes.sizeof(modules):
            break
        capacity = needed.value // ctypes.sizeof(wintypes.HMODULE) + 1
    paths = []
    for module in modules[:needed.value // ctypes.sizeof(wintypes.HMODULE)]:
        buffer = ctypes.create_unicode_buffer(32768)
        length = kernel32.GetModuleFileNameW(module, buffer, len(buffer))
        if not length:
            raise ctypes.WinError(ctypes.get_last_error())
        require(length < len(buffer), 'Loaded module path was truncated')
        paths.append(Path(buffer.value))
    return paths


def loaded_snapshot(manifest, required=False):
    expected = {name.lower(): digest for name, digest in manifest['dlls'].items()}
    directory = Path(sys.prefix) / 'share' / 'angle' / 'bin'
    records = []
    found = set()
    for path in module_paths():
        name = path.name.lower()
        if name not in expected:
            continue
        require(canonical_path(path) == canonical_path(directory / path.name),
                'ANGLE DLL loaded from unexpected directory: {}'.format(path))
        digest = sha256(path)
        require(digest == expected[name],
                'Loaded ANGLE DLL hash mismatch: {}'.format(path))
        found.add(name)
        records.append({'path': str(path), 'sha256': digest})
    cgl = sys.modules.get('kivy.graphics.cgl')
    backend = cgl.cgl_get_initialized_backend_name() if cgl else None
    complete = REQUIRED_MODULES.issubset(found) and backend == manifest['backend']
    if required:
        require(complete, 'No loaded EGL/GLES witness with initialized backend {} '
                '(found {}; backend {})'.format(
                    manifest['backend'], sorted(found), backend))
    return {'modules': records, 'initialized_backend': backend,
            'missing_modules': sorted(set(expected) - found), 'complete': complete}


_manifest = None
_events = []
_witness = False
_failure = None


def record(event, **values):
    item = {'event': event, 'pid': os.getpid(), **values}
    _events.append(item)
    print('ANGLE_DIAGNOSTIC ' + json.dumps(item), flush=True)
    output = Path(os.environ['ANGLE_DIAGNOSTIC_OUTPUT'])
    output.write_text(json.dumps({'manifest': _manifest, 'events': _events},
                                 indent=2) + '\n', encoding='utf8')


def pytest_sessionstart(session):
    global _manifest
    import pytest

    try:
        _manifest = json.loads(Path(os.environ['ANGLE_DIAGNOSTIC_MANIFEST'])
                               .read_text(encoding='utf8'))
        record('installed_before_tests', records=verify_installed(_manifest))
    except Exception as error:
        record('identity_failure', stage='sessionstart', error=str(error))
        raise pytest.UsageError(str(error)) from error


def pytest_runtest_logreport(report):
    global _witness, _failure
    import pytest

    if report.when != 'call' or _witness:
        return
    try:
        snapshot = loaded_snapshot(_manifest)
        if snapshot['complete']:
            record('loaded_during_tests', nodeid=report.nodeid, **snapshot)
            _witness = True
    except Exception as error:
        _failure = str(error)
        record('identity_failure', stage='runtest', error=_failure)
        pytest.exit(_failure, returncode=1)


def pytest_sessionfinish(session, exitstatus):
    import pytest

    try:
        record('installed_after_tests', records=verify_installed(_manifest))
        snapshot = loaded_snapshot(_manifest, required=not _witness)
        record('loaded_at_finish', **snapshot)
        require(_failure is None, _failure)
        require(_witness, 'No in-test loaded ANGLE DLL witness was recorded')
        record('completed', pytest_exitstatus=int(exitstatus),
               tests_collected=session.testscollected, identity_verified=True)
    except Exception as error:
        record('identity_failure', stage='sessionfinish', error=str(error))
        if not exitstatus:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['prepare'])
    parser.add_argument('--profile', choices=['stable', 'development'], required=True)
    parser.add_argument('--native-dir', type=Path, required=True)
    parser.add_argument('--wheel-dir', type=Path, required=True)
    parser.add_argument('--manifest', type=Path, required=True)
    options = parser.parse_args()
    prepare(options.profile, options.native_dir, options.wheel_dir, options.manifest)
