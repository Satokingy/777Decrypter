"""Console-subsystem helper; GUI invokes it with a hidden window and log handles."""
import sys,traceback
if __name__=='__main__':
    if sys.stdout:sys.stdout.reconfigure(encoding='utf8',errors='replace')
    if sys.stderr:sys.stderr.reconfigure(encoding='utf8',errors='replace')
    print('Loading offline RM5 decoder',flush=True)
    # Preload native dependencies so startup errors precede conversion output.
    import unicorn
    _bootstrap=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM)
    _bootstrap.mem_map(0x100000,4096)
    import numpy
    from Crypto.Cipher import AES
    import capstone
    import rm5_runtime
    import rm5_native
    if '--diagnose' in sys.argv:
        print('import unicorn',flush=True)
        import unicorn
        print('create arm64',flush=True)
        u=unicorn.Uc(unicorn.UC_ARCH_ARM64,unicorn.UC_MODE_ARM)
        print('map',flush=True);u.mem_map(0x100000,4096)
        print('numpy',flush=True);import numpy
        print('crypto',flush=True);from Crypto.Cipher import AES
        print('capstone',flush=True);import capstone
        print('runtime',flush=True);import rm5_runtime
        print('native',flush=True);import rm5_native
        print('READY',flush=True);sys.exit(0)
    import convert_rm5
