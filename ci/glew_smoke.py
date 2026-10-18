"""Render with published Kivy 2.3.1 and a candidate Windows GLEW wheel.

Run in a fresh Windows environment after installing Kivy's binary wheel and
the candidate runtime wheel: python ci/glew_smoke.py path/to/glew.whl
"""

import argparse
import ctypes
from ctypes import wintypes
from email.parser import BytesParser
import hashlib
import json
import os
from pathlib import Path
import re
import sys
from zipfile import ZipFile


def candidate_identity(wheel):
    """Read the runtime distribution version and expected DLL bytes from a wheel."""
    with ZipFile(wheel) as archive:
        metadata = [name for name in archive.namelist()
                    if name.endswith('.dist-info/METADATA')]
        dlls = [name for name in archive.namelist()
                if name.lower().endswith('/share/glew/bin/glew32.dll')]
        if len(metadata) != 1 or len(dlls) != 1:
            raise ValueError('Expected one GLEW runtime distribution and DLL')
        package = BytesParser().parsebytes(archive.read(metadata[0]))
        name = re.sub(r'[-_.]+', '-', package.get('Name', '')).lower()
        if name != 'kivy-deps-glew' or not package.get('Version'):
            raise ValueError('Expected the kivy_deps.glew runtime wheel')
        return package['Version'], hashlib.sha256(archive.read(dlls[0])).hexdigest()


def loaded_glew():
    """Find the DLL already loaded by Kivy, without loading a substitute."""
    kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE
    kernel32.GetModuleFileNameW.argtypes = [
        wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD]
    kernel32.GetModuleFileNameW.restype = wintypes.DWORD
    handle = kernel32.GetModuleHandleW('glew32.dll')
    if not handle:
        raise RuntimeError('Kivy did not load glew32.dll')
    buffer = ctypes.create_unicode_buffer(32768)
    length = kernel32.GetModuleFileNameW(handle, buffer, len(buffer))
    if not length or length == len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    return handle, Path(buffer.value).resolve()


def render_pixel():
    from kivy.graphics import ClearBuffers, ClearColor, Color, Fbo, Rectangle

    fbo = Fbo(size=(8, 8))
    with fbo:
        ClearColor(0, 0, 0, 1)
        ClearBuffers()
        Color(1, 0, 0, 1)
        Rectangle(pos=(0, 0), size=(8, 8))
    fbo.draw()
    offset = (4 * 8 + 4) * 4
    pixel = tuple(fbo.pixels[offset:offset + 4])
    if len(pixel) != 4 or any(abs(value - expected) > 1
                              for value, expected in zip(pixel, (255, 0, 0, 255))):
        raise RuntimeError('GLEW FBO pixel mismatch: {!r}'.format(pixel))
    return pixel


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('wheel', type=Path)
    args = parser.parse_args()
    if sys.platform != 'win32' or ctypes.sizeof(ctypes.c_void_p) != 8:
        parser.error('This smoke requires Windows x64 and the candidate Windows DLL')
    version, expected_hash = candidate_identity(args.wheel)
    os.environ['KIVY_GL_BACKEND'] = 'glew'
    os.environ.setdefault('KIVY_NO_ARGS', '1')

    import kivy
    from kivy.base import EventLoop
    from kivy.core.window import Window
    from kivy.graphics.cgl import cgl_get_initialized_backend_name
    from kivy.graphics.opengl import GL_RENDERER, GL_VENDOR, GL_VERSION, glGetString
    import kivy_deps.glew

    if kivy.__version__ != '2.3.1' or kivy_deps.glew.__version__ != version:
        raise RuntimeError('Expected Kivy 2.3.1 and candidate GLEW ' + version)
    EventLoop.ensure_window()
    try:
        backend = cgl_get_initialized_backend_name()
        if backend != 'glew':
            raise RuntimeError('Expected initialized glew backend, got ' + str(backend))
        handle, path = loaded_glew()
        expected_path = Path(sys.prefix) / 'share/glew/bin/glew32.dll'
        dll_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        if not path.samefile(expected_path) or dll_hash != expected_hash:
            raise RuntimeError('Loaded GLEW DLL does not match the candidate wheel: ' + str(path))
        # Reuse the observed module handle; do not load another GLEW for this check.
        glew = ctypes.WinDLL(str(path), handle=handle)
        glew.glewIsSupported.argtypes = [ctypes.c_char_p]
        glew.glewIsSupported.restype = ctypes.c_ubyte
        glew.glewGetString.argtypes = [ctypes.c_uint]
        glew.glewGetString.restype = ctypes.c_char_p
        details = {
            'kivy': kivy.__version__, 'glew_package': version, 'backend': backend,
            'dll': str(path), 'sha256': dll_hash,
            'glew_native': glew.glewGetString(1).decode('ascii'),  # GLEW_VERSION
            'gl_version': glGetString(GL_VERSION).decode('ascii'),
            'gl_vendor': glGetString(GL_VENDOR).decode('ascii'),
            'gl_renderer': glGetString(GL_RENDERER).decode('ascii'),
        }
        print(json.dumps(details, sort_keys=True), flush=True)
        if not glew.glewIsSupported(b'GL_VERSION_2_0'):
            raise RuntimeError('GLEW did not initialize OpenGL 2.0 support')
        details['pixel'] = render_pixel()
        print('GLEW smoke passed: ' + json.dumps(details, sort_keys=True), flush=True)
    finally:
        Window.close()


if __name__ == '__main__':
    main()
