"""Unicorn emits JIT code. Disable CFG on this isolated worker's PE only.

The GUI keeps the default bootloader settings. No system settings are changed.
PyInstaller's CFG-enabled bootloader otherwise fails with 0xc0000409 when
Unicorn enters generated code. Python's normal host also has GUARD_CF unset.
"""
from pathlib import Path
import pefile
p=Path('dist/PBVideoWorker/PBVideoWorker.exe')
pe=pefile.PE(str(p));pe.OPTIONAL_HEADER.DllCharacteristics &= ~0x4000
data=pe.write();pe.close();p.write_bytes(data)
