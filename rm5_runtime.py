"""Trace secondary stage (AES image entry) for writes to portal BASE / INIT holes."""
from __future__ import annotations
import struct
from pathlib import Path
from unicorn import (
    Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_PROT_ALL,
    UC_HOOK_CODE, UC_HOOK_BLOCK, UC_HOOK_MEM_UNMAPPED, UC_HOOK_INTR, UC_HOOK_MEM_WRITE,
)
from unicorn.arm64_const import *

import sys
ASSETS = Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / 'assets'
ROOT = ASSETS / 'video'
ELF = (ROOT / "libSevenPortal.runtime.so").read_bytes()
APK=b""
AES = (ROOT / "stage1_util.bin").read_bytes()
import tempfile
OUT = Path(tempfile.gettempdir()) / "PBAssetTool"
OUT.mkdir(parents=True,exist_ok=True)
BASE = 0x7000000000
AES_BASE = 0xC4000000
STACK = 0x7E00000000
STACK_SZ = 0x800000
RET = 0x7E10000000
ENTRY = AES_BASE + 0x5D4

mu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
mu.mem_map(STACK, STACK_SZ, UC_PROT_ALL)
mu.mem_map(RET, 0x1000, UC_PROT_ALL)
mu.mem_write(RET, struct.pack("<I", 0xD65F03C0))

# map portal RX sparse
mapped = set()
def map_page(abs_page):
    if abs_page in mapped: return
    try: mu.mem_map(abs_page, 0x1000, UC_PROT_ALL)
    except: return
    mapped.add(abs_page)
    off = abs_page - BASE
    if off >= 0x3e61000:
        off = off - 0x10000 if off < 0x462a2e8 else len(ELF)
    if 0 <= off < len(ELF):
        chunk = ELF[off:off+0x1000]
        mu.mem_write(abs_page, chunk + b"\x00"*(0x1000-len(chunk)))
    else:
        mu.mem_write(abs_page, b"\x00"*0x1000)

for va in range(0, 0x20000, 0x1000):
    map_page(BASE+va)
for va in range(0x1030000, 0x15d0000, 0x1000):
    map_page(BASE+va)
for va in range(0x3e61000, 0x3e64000, 0x1000):
    map_page(BASE+va)

# map AES image full
aes_sz = (len(AES) + 0xFFF) & ~0xFFF
mu.mem_map(AES_BASE, max(aes_sz, 0x30000), UC_PROT_ALL)
mu.mem_write(AES_BASE, AES + b"\x00"*(max(aes_sz,0x30000)-len(AES)))

writes = [];dirty_pages=set()
def on_write(mu, access, address, size, value, user):
    # any write to portal base region
    if BASE <= address < BASE + 0x5000000:
        dirty_pages.add(address&~4095)
        if len(writes)<100000:writes.append((address - BASE, size, value & ((1<<(8*min(size,8)))-1)))
    # writes within AES image past code (ctx)
    if AES_BASE + 0x20000 <= address < AES_BASE + 0x26000:
        writes.append((("aes", address - AES_BASE), size, value))




def on_unmapped(mu, access, address, size, value, user):
    if BASE <= address < BASE + 0x1879e000:
        map_page(address & ~0xFFF)
        return True
    print('UNMAPPED',hex(address),'access',access,'regs',[hex(mu.reg_read(r)) for r in [UC_ARM64_REG_LR,UC_ARM64_REG_X16,UC_ARM64_REG_X17,UC_ARM64_REG_X19,UC_ARM64_REG_X20]],flush=True)
    return False
mu.hook_add(UC_HOOK_MEM_UNMAPPED, on_unmapped)

# Explicit offline file system and syscall results; no blanket-success stubs.
import json
symlinks={'/data/user/0/jp.sammynet.next.ort.a0125/lib':'/data/app/jp.sammynet.next.ort.a0125-1/lib/arm64','/proc/self/exe':'/system/bin/app_process64','/proc/12345/exe':'/system/bin/app_process64','/proc/self':'/proc/12345'}
vdirs=set(['/','/data/app/jp.sammynet.next.ort.a0125-1','/data/app/jp.sammynet.next.ort.a0125-1/lib','/data/app/jp.sammynet.next.ort.a0125-1/lib/arm64','/data/user/0/jp.sammynet.next.ort.a0125/lib','/proc','/proc/self','/proc/12345','/proc/12345/task','/proc/12345/task/12345','/system/lib64','/system/lib','/system','/system/bin','/data','/data/app','/data/user','/data/user/0','/data/user/0/jp.sammynet.next.ort.a0125','/data/data','/data/data/jp.sammynet.next.ort.a0125']);vfiles={'/system/bin/app_process64':b''};vmodes={};virtual_ns=[1700000000000000000];filelocks={};rlimits={};fds={};fd_next=[3];heap_next=[0xD0000000];events=[]
so_path='/data/app/jp.sammynet.next.ort.a0125-1/lib/arm64/libSevenPortal.so'
maps=(f'7200000000-7200010000 r-xp 00000000 00:01 3 /system/bin/app_process64\n'+f'{BASE:x}-{BASE+0x3e51000:x} r-xp 00000000 00:01 1 {so_path}\n'+f'{BASE+0x3e61000:x}-{BASE+0x187a0000:x} rw-p 03e51000 00:01 1 {so_path}\n').encode()
# NDK files are symbol stubs, used only for loader metadata.
# Execution of any exported function is intercepted and stops unless implemented.
import sys,io
sys.path.insert(0,str((ROOT / 'deps').resolve()))
from elftools.elf.elffile import ELFFile
ndk=(ROOT / 'ndk')
libfiles={};imports={}
for index,name in enumerate(['liblog.so','libstdc++.so','libm.so','libc.so','libz.so','libdl.so']):
 raw=(ndk/name).read_bytes();libfiles['/system/lib64/'+name]=raw;elf=ELFFile(io.BytesIO(raw));base=0x7100000000+index*0x1000000
 for seg in elf.iter_segments():
  if seg['p_type']!='PT_LOAD':continue
  low=int(seg['p_vaddr'])&~4095;high=(int(seg['p_vaddr'])+int(seg['p_memsz'])+4095)&~4095
  for page in range(low,high,4096):
   try:mu.mem_map(base+page,4096,UC_PROT_ALL)
   except:pass
  mu.mem_write(base+int(seg['p_vaddr']),seg.data())
  maps+=f"{base+low:x}-{base+high:x} r-xp {int(seg['p_offset'])&~4095:08x} 00:01 2 /system/lib64/{name}\n".encode()
 for sym in elf.get_section_by_name('.dynsym').iter_symbols():
  if sym['st_info']['type']=='STT_FUNC' and sym['st_shndx']!='SHN_UNDEF':imports[base+int(sym['st_value'])]=name+':'+sym.name
def cstr(addr):
 return bytes(mu.mem_read(addr,512)).split(b'\0')[0].decode('utf8','replace')
def filedata(path):
 if path=="/proc/sys/fs/lease-break-time":return b"45\n"
 path=path.rstrip("/") or "/"
 if path in ["/proc/self/comm","/proc/12345/comm"]:return b"jp.sammynet.next.ort.a0125"[-15:]+b"\n"
 if path in ['/default.prop','/system/build.prop','/system/default.prop']:return b'ro.secure=1\nro.debuggable=0\nro.build.type=user\nro.build.tags=release-keys\nro.product.cpu.abi=arm64-v8a\nro.build.version.release=5.0\n'
 if path in ['/proc/self/exe','/proc/12345/exe']:return vfiles['/system/bin/app_process64']
 if path.endswith('/base.apk'):return APK
 if path in libfiles:return libfiles[path]
 if path in vdirs:return b''
 if path in vfiles:return vfiles[path]
 if path in ['/proc/self/maps','/proc/12345/maps']:return maps
 if path in ['/proc/self/cmdline','/proc/12345/cmdline']:return b'jp.sammynet.next.ort.a0125\0'
 if path=='/proc/self/environ':return b'PATH=/system/bin\0ANDROID_DATA=/data\0ANDROID_ROOT=/system\0EXTERNAL_STORAGE=/sdcard\0'
 if path.endswith('/libSevenPortal.so'):return ELF
 if path in ['/proc/self/status','/proc/12345/status','/proc/12345/task/12345/status']:return b'Name: jp.sammynet.next.ort.a0125\nState: R (running)\nPid: 12345\nTgid: 12345\nPPid: 1\nTracerPid: 0\nUid: 10125 10125 10125 10125\n'
 return None
def on_intr(mu,intno,user):
 nr=mu.reg_read(UC_ARM64_REG_X8);args=[mu.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2]];a,c,d=args;rv=-38;ev={'nr':nr,'args':args,'pc':hex(mu.reg_read(UC_ARM64_REG_PC))}
 if nr==222:
  size=(c+4095)&~4095;rv=heap_next[0];heap_next[0]+=size+4096;mu.mem_map(rv,size,UC_PROT_ALL)
  flags=mu.reg_read(UC_ARM64_REG_X3);fd=mu.reg_read(UC_ARM64_REG_X4);offset=mu.reg_read(UC_ARM64_REG_X5)
  if not flags&0x20:
   if fd not in fds:raise RuntimeError('mmap unknown file')
   mu.mem_write(rv,fds[fd][0][offset:offset+c])
 elif nr in (215,226):
  rv=0
  if nr==226:
   if BASE<=a and a+c<=BASE+0x1879e000:
    lo=a&~4095;hi=(a+c+4095)&~4095;page=lo
    while page<hi:
     if page in mapped:page+=4096;continue
     start=page
     while page<hi and page not in mapped:page+=4096
     mu.mem_map(start,page-start,UC_PROT_ALL);mapped.update(range(start,page,4096))
     for vstart,vend,delta in [(0,0x3e51000,0),(0x3e61000,0x462a2e8,-0x10000)]:
      left=max(start,BASE+vstart);right=min(page,BASE+vend)
      if right>left:mu.mem_write(left,ELF[left-BASE+delta:right-BASE+delta])
   codebytes=bytes(mu.mem_read(a,c));(OUT/f'executable_{a:x}_{c:x}.bin').write_bytes(codebytes)
   for signature,callback in [(checksum_signature,fast_checksum),(process_scan_signature,skip_process_scan),(report_signature,error_trace),(art_guard_signature,skip_art_guard),(dump_guard_signature,skip_dump_guard),(fork_guard_signature,skip_fork_guard),(helper_guard_signature,skip_helper_guard)]:
    off=codebytes.find(signature)
    if off>=0:
     mu.hook_add(UC_HOOK_CODE,callback,begin=a+off,end=a+off);print('SIGNATURE_HOOK',callback.__name__,hex(a+off),flush=True)
   print('EXECUTABLE',hex(a),hex(c),flush=True)
 elif nr==32:
  if a not in fds:rv=-9
  else:
   path=fds[a][2]
   if c&8:filelocks.pop(path,None);rv=0
   elif path in filelocks and filelocks[path]!=a:rv=-11
   else:filelocks[path]=a;rv=0
 elif nr==101:
  sec,nsec=struct.unpack('<qq',bytes(mu.mem_read(a,16)));virtual_ns[0]+=sec*1000000000+nsec;ev['sleep_ns']=sec*1000000000+nsec;rv=0
 elif nr==113:mu.mem_write(c,struct.pack('<qq',virtual_ns[0]//1000000000,virtual_ns[0]%1000000000));rv=0
 elif nr==169:mu.mem_write(a,struct.pack('<qq',virtual_ns[0]//1000000000,virtual_ns[0]%1000000000//1000));rv=0
 elif nr==164:rlimits[a]=bytes(mu.mem_read(c,16));rv=0
 elif nr==163:mu.mem_write(c,rlimits.get(a,struct.pack('<QQ',0xffffffffffffffff,0xffffffffffffffff)));rv=0
 elif nr==34:
  path=cstr(c);ev['path']=path;rv=-17 if path in vdirs else 0;vdirs.add(path)
 elif nr==56:
  path=cstr(c);ev['path']=path;data=filedata(path)
  if data is None and d&64 and path.rsplit('/',1)[0] in vdirs:vfiles[path]=b'';data=b''
  if data is not None:rv=fd_next[0];fd_next[0]+=1;fds[rv]=[data,0,path]
  else:rv=-2
 elif nr==78:
  path=cstr(c);ev['path']=path
  if path in symlinks or path=='/system/bin/app_process':
   target=symlinks.get(path,'/system/bin/app_process64').encode();limit=mu.reg_read(UC_ARM64_REG_X3);part=target[:limit];mu.mem_write(d,part);rv=len(part)
  else:rv=-22
 elif nr==61:
  if a not in fds:rv=-9
  else:
   data,pos,path=fds[a];names=['.','..']+(['12345','self'] if path=='/proc' else ['12345'] if path.endswith('/task') else [])
   records=bytearray()
   for i,name in enumerate(names[pos:]):
    recsize=(19+len(name)+1+7)&~7;entry=struct.pack('<QqHB',pos+i+1,pos+i+1,recsize,4)+name.encode()+b'\0';records.extend(entry.ljust(recsize,b'\0'))
   if len(records)>d:raise RuntimeError('small getdents buffer')
   mu.mem_write(c,bytes(records));fds[a][1]=len(names);rv=len(records);ev['path']=path
 elif nr==64:
  if a in fds:
   data,pos,path=fds[a];part=bytes(mu.mem_read(c,d));data=data[:pos].ljust(pos,b'\0')+part+data[pos+d:];fds[a]=[data,pos+d,path];vfiles[path]=data;rv=d;ev['path']=path
  else:rv=-9
 elif nr==46:
  if a in fds:
   data,pos,path=fds[a];data=data[:c].ljust(c,b'\0');fds[a][0]=data;vfiles[path]=data;rv=0
  else:rv=-9
 elif nr==82:rv=0 if a in fds else -9
 elif nr==63:
  if a in fds:
   data,pos,path=fds[a];part=data[pos:pos+d];mu.mem_write(c,part);fds[a][1]+=len(part);rv=len(part);ev['path']=path
  else:rv=-9
 elif nr==62:
  if a in fds:
   data,pos,path=fds[a];offset=c if c<1<<63 else c-(1<<64);rv=offset+(pos if d==1 else len(data) if d==2 else 0);fds[a][1]=rv
  else:rv=-9
 elif nr==57:
  rv=0 if a in fds else -9;fds.pop(a,None)
 elif nr in (79,80):
  path=(cstr(c) if nr==79 else fds.get(a,[None,0,''])[2]).rstrip('/') or '/';ev['path']=path;data=filedata(path)
  if data is not None:
   st=bytearray(128);struct.pack_into('<I',st,16,(0o40000 if path in vdirs else 0o100000)|vmodes.get(path,0o755 if path in vdirs else 0o644));struct.pack_into('<I',st,16,0o120777 if nr==79 and mu.reg_read(UC_ARM64_REG_X3)&256 and path in symlinks else struct.unpack_from('<I',st,16)[0]);owner=10125 if path.startswith(('/data/user/0/jp.sammynet.next.ort.a0125','/data/data/jp.sammynet.next.ort.a0125','/proc/self','/proc/12345')) else 0;struct.pack_into('<II',st,24,owner,owner);struct.pack_into('<q',st,48,len(data));mu.mem_write(d if nr==79 else c,bytes(st));rv=0
  else:rv=-2
 elif nr in (172,178):rv=12345
 elif nr in (93,94):ev['exit']=a;rv=0;mu.emu_stop()
 else:ev['unimplemented']=True;mu.emu_stop()
 ev['result']=rv;events.append(ev);print(ev,flush=True);mu.reg_write(UC_ARM64_REG_X0,rv&0xffffffffffffffff)
mu.hook_add(UC_HOOK_INTR,on_intr)
from collections import deque
trace=deque(maxlen=24)
blocks=deque(maxlen=256)
def on_block(mu,address,size,user):
 blocks.append((address,mu.reg_read(UC_ARM64_REG_LR),mu.reg_read(UC_ARM64_REG_X0)))

def error_trace(mu,address,size,user):
 print('ERROR_REPORT',hex(address),'lr',hex(mu.reg_read(UC_ARM64_REG_LR)),[hex(mu.reg_read(r)) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]],flush=True)
 try:
  ptr=struct.unpack('<Q',bytes(mu.mem_read(mu.reg_read(UC_ARM64_REG_SP),8)))[0];print('ERROR_DETAIL',cstr(ptr) if ptr else '',flush=True)
 except Exception as e:print('ERROR_DETAIL unavailable',str(e),flush=True)
 (OUT/'error_blocks.json').write_text(json.dumps([[hex(v) for v in row] for row in blocks]))

n=[0]
hot={}
from Crypto.Cipher import AES as CipherAES
sys.path.insert(0,str(ROOT/'tools'))
from scramble import e9b0_forward
master=(ROOT / 'stage101/masterkey.bin').read_bytes()
crypt_count=[0];dlerr=[False];tlskeys={};tlsvalues={};signals={};zstreams={};thread_attrs={};thread_stacks=set();thread_jobs={};pending_threads=[];thread_frames=[];stream_fds={};directories={};streams={};allocations={};mutexes={};dumpable=[1];environment={"PATH":"/system/bin","ANDROID_DATA":"/data","ANDROID_ROOT":"/system","EXTERNAL_STORAGE":"/sdcard"}
def on_code(mu, address, size, user):
    if not (AES_BASE<=address<AES_BASE+0x30000 or BASE<=address<BASE+0x19000000 or 0x7100000000<=address<0x7106000000 or address==RET):
        print('unexpected execution',hex(address),list(trace),flush=True);mu.emu_stop();return
    if address in [AES_BASE+0xb5d4,AES_BASE+0xb6f8]:
        dest=mu.reg_read(UC_ARM64_REG_X0);arg=mu.reg_read(UC_ARM64_REG_X1);size=mu.reg_read(UC_ARM64_REG_X2)
        if size>0x4000000:print('oversized memory operation',size,flush=True);mu.emu_stop();return
        data=bytes([arg&255])*size if address==AES_BASE+0xb5d4 else bytes(mu.mem_read(arg,size))
        mu.mem_write(dest,data);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR));return
    if address in [AES_BASE+0x181c,AES_BASE+0xe3d4,AES_BASE+0xf4d0]:
        a,b,c,d=[mu.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]]
        if address==AES_BASE+0x181c:
            a&=0xffffffff;b&=0xffffffff;result=0
            while a:
                if a&1:result^=b
                b=((b<<1)^(0x579357eb if b&0x80000000 else 0))&0xffffffff;a>>=1
        elif address==AES_BASE+0xe3d4:
            mu.mem_write(b,e9b0_forward(bytes(mu.mem_read(b,c)),a));result=1
        else:
            assert bytes(mu.mem_read(c,244))==AES[0x25280:0x25374]
            data=bytes(mu.mem_read(a,b));size=b//16*16
            out=CipherAES.new(master,CipherAES.MODE_CBC,iv=bytes(16)).decrypt(data[:size])+data[size:]
            mu.mem_write(a,out);result=1;crypt_count[0]+=1
            (OUT/f'decrypt_{crypt_count[0]:04d}.bin').write_bytes(out)
            print('DECRYPT',crypt_count[0],hex(a),len(out),out[:32].hex(),flush=True)
        mu.reg_write(UC_ARM64_REG_X0,result&0xffffffffffffffff);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR));return
    if address in imports:
        name=imports[address].split(':',1)[1];a,b,c=[mu.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2]]
        if name=='dlopen':
            path=cstr(a) if a else '';result=next((0x7100000000+i*0x1000000 for i,nm in enumerate(['liblog.so','libstdc++.so','libm.so','libc.so','libz.so','libdl.so']) if path.split('/')[-1]==nm),0)
            dlerr[0]=not bool(result);print('DLOPEN',path,hex(result),flush=True)
        elif name=='dlsym':
            symbol=cstr(b);result=byname.get(symbol,0);dlerr[0]=not bool(result);print('DLSYM',hex(a),symbol,hex(result),flush=True)
        elif name=='__system_property_get':
            prop=cstr(a);value={'ro.build.type':'user','ro.secure':'1','ro.debuggable':'0','ro.adb.secure':'1','ro.build.tags':'release-keys','sys.usb.config':'mtp','ro.build.version.release':'5.0','ro.build.version.sdk':'21','ro.product.cpu.abi':'arm64-v8a','ro.product.cpu.abilist':'arm64-v8a,armeabi-v7a,armeabi'}.get(prop,'').encode()
            mu.mem_write(b,value+b'\0');result=len(value);print('PROPERTY',prop,value,flush=True)
        elif name=='getenv':
            env=cstr(a);print('GETENV',env,flush=True);result=STACK+0x3000 if env in environment else 0
            if result:mu.mem_write(result,environment[env].encode()+b'\0')
        elif name in ['malloc','calloc','realloc']:
            size=a*b if name=='calloc' else b if name=='realloc' else a;size=max(size,1)
            if size>0x20000000:raise RuntimeError('allocation too large')
            result=heap_next[0];span=(size+4095)&~4095;heap_next[0]+=span+4096;mu.mem_map(result,span);allocations[result]=size
            if name=='realloc' and a:mu.mem_write(result,bytes(mu.mem_read(a,min(size,allocations[a]))))
        elif name=='free':
            if a in allocations:
                length=allocations.pop(a);mu.mem_unmap(a,(max(length,1)+4095)&~4095)
            elif a:raise RuntimeError('free of unknown allocation '+hex(a))
            result=0
        elif name in ['memcpy','memmove','__memcpy_chk']:
            mu.mem_write(a,bytes(mu.mem_read(b,c)));result=a
        elif name=='memset':mu.mem_write(a,bytes([b&255])*c);result=a
        elif name in ['strlen','__strlen_chk']:result=len(cstr(a).encode())
        elif name=='strcmp':result=(cstr(a)>cstr(b))-(cstr(a)<cstr(b))
        elif name=='strncmp':result=(cstr(a)[:c]>cstr(b)[:c])-(cstr(a)[:c]<cstr(b)[:c])
        elif name in ['setenv','unsetenv']:
            env=cstr(a)
            if name=='setenv':environment[env]=cstr(b)
            else:environment.pop(env,None)
            print('ENV_WRITE',env,environment.get(env),flush=True);result=0
        elif name=='vsnprintf':
            import re
            fmt=cstr(c);vp=mu.reg_read(UC_ARM64_REG_X3);vs,gr,vr,go,vo=struct.unpack('<QQQii',bytes(mu.mem_read(vp,32)))
            def sub(m):
                nonlocal vs,go
                spec=m.group(0)
                if spec=='%%':return '%'
                ptr=gr+go if go<0 else vs
                if go<0:go+=8
                else:vs+=8
                v=struct.unpack('<Q',bytes(mu.mem_read(ptr,8)))[0];kind=spec[-1]
                if kind=='s':return cstr(v) if v else '(null)'
                if kind=='p':return hex(v)
                width=re.search(r'\d+',spec);w=int(width.group()) if width else 0
                if kind in 'xX':out=format(v,kind)
                elif kind in 'dui':out=str(v)
                elif kind=='c':out=chr(v&255)
                else:raise RuntimeError('unsupported format '+spec)
                return out.rjust(w,'0' if spec.startswith('%0') else ' ')
            out=re.sub(r'%(?:[-+ #0]*\d*(?:\.\d+)?[hlzjt]*[diuxXscp]|%)',sub,fmt).encode()
            print('FORMAT',fmt,out,flush=True)
            if b:mu.mem_write(a,out[:b-1]+b'\0')
            result=len(out)
        elif name=='pthread_mutex_init':mutexes[a]=False;mu.mem_write(a,bytes(40));result=0
        elif name in ['pthread_mutex_lock','pthread_mutex_trylock']:
            if mutexes.get(a,False):raise RuntimeError('contended mutex unsupported')
            mutexes[a]=True;result=0
        elif name=='pthread_mutex_unlock':
            result=0 if mutexes.get(a,False) else 1;mutexes[a]=False
        elif name=='pthread_mutex_destroy':mutexes.pop(a,None);result=0
        elif name=='prctl':
            print('PRCTL',a,b,flush=True)
            if a==3:result=dumpable[0]
            elif a==4:dumpable[0]=b;result=0
            else:raise RuntimeError('unimplemented prctl')
        elif name=='fopen':
            path=cstr(a);mode=cstr(b);data=filedata(path);print('FOPEN',path,mode, data is not None,'LR',hex(mu.reg_read(UC_ARM64_REG_LR)),'FP',hex(mu.reg_read(UC_ARM64_REG_X29)),flush=True);(OUT/'fopen_stack.bin').write_bytes(bytes(mu.mem_read(STACK,STACK_SZ)))
            if ('a' in mode or 'w' in mode) and path.rsplit('/',1)[0] in vdirs:
                if data is None or 'w' in mode:vfiles[path]=b'';data=b''
            if not path:
                print('STOP empty fopen for diagnosis',flush=True);mu.emu_stop();return
            if data is None:result=0;mu.mem_write(STACK+0x1000,struct.pack('<i',2))
            else:
                result=heap_next[0];heap_next[0]+=8192;mu.mem_map(result,4096);streams[result]=[data,len(data) if 'a' in mode else 0,path]
        elif name=='fclose':result=0 if a in streams else -1;streams.pop(a,None)
        elif name=='fgets':
            data,pos,path=streams[c];end=data.find(b'\n',pos);end=len(data) if end<0 else end+1;part=data[pos:min(end,pos+b-1)]
            if part:mu.mem_write(a,part+b'\0');streams[c][1]+=len(part);result=a
            else:result=0
        elif name=='fread':
            stream=mu.reg_read(UC_ARM64_REG_X3);data,pos,path=streams[stream];part=data[pos:pos+b*c];mu.mem_write(a,part);streams[stream][1]+=len(part);result=len(part)//b if b else 0
        elif name=='fseek':
            data,pos,path=streams[a];offset=b if b<1<<63 else b-(1<<64);new=offset+(pos if c==1 else len(data) if c==2 else 0)
            if new<0:result=-1
            else:streams[a][1]=new;result=0
        elif name=='ftell':result=streams[a][1]
        elif name=='fwrite':
            stream=mu.reg_read(UC_ARM64_REG_X3);data,pos,path=streams[stream];part=bytes(mu.mem_read(a,b*c));data=data[:pos].ljust(pos,b'\0')+part+data[pos+len(part):];streams[stream]=[data,pos+len(part),path];vfiles[path]=data;result=c
        elif name=='fputs':
            data,pos,path=streams[b];part=cstr(a).encode();data=data[:pos].ljust(pos,b'\0')+part+data[pos+len(part):];streams[b][:]=[data,pos+len(part),path];vfiles[path]=data;result=len(part)
        elif name=='fflush':result=0
        elif name=='fileno':
            if a not in stream_fds:stream_fds[a]=fd_next[0];fds[fd_next[0]]=streams[a];fd_next[0]+=1
            result=stream_fds[a]
        elif name=='fcntl':
            print('FCNTL',a,b,hex(c),flush=True)
            if a not in fds:result=-1
            elif b in [1,2,3,4,6,7]:result=0
            elif b==5:mu.mem_write(c,struct.pack('<h',2));result=0
            else:raise RuntimeError('unimplemented fcntl')
        elif name=='feof':result=int(streams[a][1]>=len(streams[a][0]))
        elif name=='opendir':
            path=cstr(a).rstrip('/') or '/';print('OPENDIR',path,flush=True)
            if path not in vdirs:result=0;mu.mem_write(STACK+0x1000,struct.pack('<i',2))
            else:
                prefix=path+'/';names=sorted({q[len(prefix):].split('/')[0] for q in list(vdirs)+list(vfiles) if q.startswith(prefix)})
                result=heap_next[0];heap_next[0]+=8192;mu.mem_map(result,4096);directories[result]=[['.','..']+names,0,path]
        elif name in ['readdir','readdir64']:
            names,pos,path=directories[a]
            if pos>=len(names):result=0
            else:
                value=names[pos].encode();data=struct.pack('<QqHB',pos+1,pos+1,280,4)+value+b'\0';mu.mem_write(a+0x100,data.ljust(280,b'\0'));directories[a][1]+=1;result=a+0x100
        elif name=='closedir':result=0 if a in directories else -1;directories.pop(a,None)
        elif name=='realpath':
            path=cstr(a);print('REALPATH',path,'LR',hex(mu.reg_read(UC_ARM64_REG_LR)),flush=True);path=path.replace('/data/user/0/jp.sammynet.next.ort.a0125/lib','/data/app/jp.sammynet.next.ort.a0125-1/lib/arm64');path='/system/bin/app_process64' if path in ['/system/bin/app_process','/proc/self/exe','/proc/12345/exe'] else path
            if filedata(path) is None:result=0;mu.mem_write(STACK+0x1000,struct.pack('<i',2))
            elif b:mu.mem_write(b,path.encode()+b'\0');result=b
            else:raise RuntimeError('realpath allocation unsupported')
        elif name=='sscanf':
            import re
            source=cstr(a);fmt=cstr(b);print('SCANF',repr(source),repr(fmt),flush=True)
            parts=re.split(r'(%(?:l{1,2}|z)?[duxXsc])',fmt);pattern='';specs=[]
            for part in parts:
                if part.startswith('%'):
                    specs.append(part);pattern+=r'\s*([+-]?[0-9]+)' if part[-1] in 'du' else r'\s*([0-9a-fA-F]+)' if part[-1] in 'xX' else r'\s*(.)' if part[-1]=='c' else r'\s*(\S+)'
                else:pattern+=''.join(r'\s*' if ch.isspace() else re.escape(ch) for ch in part)
            match=re.match(pattern,source);result=0
            if match:
                regs=[UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]
                for idx,(spec,value) in enumerate(zip(specs,match.groups())):
                    if idx>=len(regs):raise RuntimeError('scanf stack varargs unsupported')
                    dst=mu.reg_read(regs[idx])
                    if spec[-1]=='s':data=value.encode()+b'\0'
                    elif spec[-1]=='c':data=value.encode()[:1]
                    else:
                        width=8 if 'l' in spec or 'z' in spec else 4;v=int(value,16 if spec[-1] in 'xX' else 10);data=(v&((1<<(width*8))-1)).to_bytes(width,'little')
                    mu.mem_write(dst,data);result+=1
        elif name=='pthread_key_create':
            key=len(tlskeys)+1;tlskeys[key]=b;mu.mem_write(a,struct.pack('<I',key));result=0
        elif name=='pthread_getspecific':result=tlsvalues.get((thread_frames[-1][0] if thread_frames else 12345,a),0)
        elif name=='pthread_setspecific':tlsvalues[(thread_frames[-1][0] if thread_frames else 12345,a)]=b;result=0
        elif name=='pthread_key_delete':tlskeys.pop(a,None);result=0
        elif name=='pthread_once':
            if BASE<=a<BASE+0x187a0000:map_page(a&~4095)
            if struct.unpack('<I',bytes(mu.mem_read(a,4)))[0]==2:result=0
            else:
                mu.mem_write(a,struct.pack('<I',2));tid=20000+len(thread_jobs);thread_jobs[tid]={'entry':b,'arg':0,'done':False}
                mu.reg_write(UC_ARM64_REG_X0,0);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR));pending_threads.append((tid,mu.context_save()));mu.emu_stop();return
        elif name=='pthread_attr_init':thread_attrs[a]={'detached':False};mu.mem_write(a,bytes(56));result=0
        elif name=='pthread_attr_setdetachstate':thread_attrs[a]['detached']=bool(b);result=0
        elif name=='pthread_attr_destroy':thread_attrs.pop(a,None);result=0
        elif name=='pthread_create':
            arg=mu.reg_read(UC_ARM64_REG_X3);tid=20000+len(thread_jobs);thread_jobs[tid]={'entry':c,'arg':arg,'done':False}
            mu.mem_write(a,struct.pack('<Q',tid));mu.reg_write(UC_ARM64_REG_X0,0);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR))
            if b and thread_attrs.get(b,{}).get('detached'):
                thread_jobs[tid]['deferred']=True;print('THREAD_DEFER detached',tid,hex(c),flush=True);return
            pending_threads.append((tid,mu.context_save()));print('THREAD_CREATE',tid,hex(c),hex(arg),flush=True);mu.emu_stop();return
        elif name=='pthread_join':
            job=thread_jobs[a]
            if not job['done']:raise RuntimeError('join before completion')
            if b:mu.mem_write(b,struct.pack('<Q',job['result']))
            result=0
        elif name=='pthread_detach':result=0 if a in thread_jobs else 3
        elif name=='pthread_self':result=thread_frames[-1][0] if thread_frames else 12345
        elif name=='getpwnam':
            account=cstr(a);print('GETPWNAM',account,flush=True);uid={'root':0,'system':1000,'shell':2000,'nobody':9999,'u0_a125':10125}.get(account)
            if uid is None:result=0
            else:
                result=STACK+0x4000;mu.mem_write(result+0x100,account.encode()+b'\0');mu.mem_write(result+0x180,b'\0/\0/system/bin/sh\0')
                mu.mem_write(result,struct.pack('<QQIIQQQ',result+0x100,result+0x180,uid,uid,result+0x180,result+0x181,result+0x183))
        elif name in ['open','__open_2']:
            path=cstr(a);data=filedata(path);print('OPEN',path,hex(b),flush=True)
            if data is None and b&64 and path.rsplit('/',1)[0] in vdirs:vfiles[path]=b'';data=b''
            if data is None:result=-1;mu.mem_write(STACK+0x1000,struct.pack('<i',2))
            else:result=fd_next[0];fd_next[0]+=1;fds[result]=[data,0,path]
        elif name in ['read','write','close','lseek','fstat','mmap','munmap','mprotect','ftruncate','fsync']:
            numbers={'read':63,'write':64,'close':57,'lseek':62,'fstat':80,'mmap':222,'munmap':215,'mprotect':226,'ftruncate':46,'fsync':82};old8=mu.reg_read(UC_ARM64_REG_X8);mu.reg_write(UC_ARM64_REG_X8,numbers[name]);on_intr(mu,2,None);mu.reg_write(UC_ARM64_REG_X8,old8);result=mu.reg_read(UC_ARM64_REG_X0)
            if result>=0xfffffffffffff000:mu.mem_write(STACK+0x1000,struct.pack('<i',(1<<64)-result));result=-1
        elif name in ['inflateInit2_','inflateInit_']:
            import zlib
            bits=(b if b<0x80000000 else b-0x100000000) if name=='inflateInit2_' else 15
            zstreams[a]=[zlib.decompressobj(bits),1];mu.mem_write(a+16,bytes(8));mu.mem_write(a+40,bytes(8));result=0
        elif name=='inflate':
            import zlib
            obj,adler=zstreams[a];src=struct.unpack('<Q',bytes(mu.mem_read(a,8)))[0];avail=struct.unpack('<I',bytes(mu.mem_read(a+8,4)))[0];dst=struct.unpack('<Q',bytes(mu.mem_read(a+24,8)))[0];cap=struct.unpack('<I',bytes(mu.mem_read(a+32,4)))[0]
            data=bytes(mu.mem_read(src,avail));out=obj.decompress(data,cap) if cap else b'';used=avail-len(obj.unused_data if obj.eof else obj.unconsumed_tail)
            mu.mem_write(dst,out);mu.mem_write(a,struct.pack('<QI',src+used,avail-used));mu.mem_write(a+24,struct.pack('<QI',dst+len(out),cap-len(out)))
            for off,inc in [(16,used),(40,len(out))]:mu.mem_write(a+off,struct.pack('<Q',struct.unpack('<Q',bytes(mu.mem_read(a+off,8)))[0]+inc))
            adler=zlib.adler32(out,adler);zstreams[a][1]=adler;mu.mem_write(a+96,struct.pack('<Q',adler));result=1 if obj.eof else 0 if used or out else -5
        elif name=='inflateEnd':zstreams.pop(a,None);result=0
        elif name=='sigemptyset':mu.mem_write(a,bytes(8));result=0
        elif name=='sigfillset':mu.mem_write(a,b'\xff'*8);result=0
        elif name=='sigaction':
            if c:mu.mem_write(c,signals.get(a,bytes(32)))
            if b:signals[a]=bytes(mu.mem_read(b,32));print('SIGACTION',a,signals[a].hex(),flush=True)
            result=0
        elif name=='chmod':
            path=cstr(a);result=0 if filedata(path) is not None else -1
            if result==0:vmodes[path]=b
        elif name=='fchmod':
            result=0 if a in fds else -1
            if a in fds:vmodes[fds[a][2]]=b
        elif name=='time':
            import time
            result=1700000000 # Fixed offline clock for reproducible allocation paths
            if a:mu.mem_write(a,struct.pack('<q',result))
        elif name in ['getuid','geteuid','getgid','getegid']:result=10125
        elif name in ['gettid','getpid']:result=12345
        elif name=='__errno':result=STACK+0x1000
        elif name=='dlerror':
            result=STACK+0x2000 if dlerr[0] else 0;mu.mem_write(STACK+0x2000,b'Unavailable in offline loader\0');dlerr[0]=False
        elif name=='dlclose':result=0
        else:
            print('IMPORT_STOP',imports[address],[hex(a),hex(b),hex(c)],flush=True);mu.emu_stop();return
        mu.reg_write(UC_ARM64_REG_X0,result&0xffffffffffffffff);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR));return
    trace.append((address,mu.reg_read(UC_ARM64_REG_LR),mu.reg_read(UC_ARM64_REG_X0),mu.reg_read(UC_ARM64_REG_X1)))
    if address < 0x100000:
        print("invalid low target",list(trace),flush=True);mu.emu_stop();return
    n[0]+=1
    if n[0] > 15_000_000:
        mu.emu_stop()
    rva = address - AES_BASE if AES_BASE <= address < AES_BASE+0x30000 else address
    if AES_BASE <= address < AES_BASE+0x10000:
        hot[rva] = hot.get(rva,0)+1
for off in [0xb5d4,0xb6f8,0x181c,0xe3d4,0xf4d0]:mu.hook_add(UC_HOOK_CODE,on_code,begin=AES_BASE+off,end=AES_BASE+off)
mu.hook_add(UC_HOOK_CODE,on_code,begin=0x7100000000,end=0x7106000000)


from capstone import Cs,CS_ARCH_ARM64,CS_MODE_ARM
rootbin=(ROOT / 'stage101_loader/executable_d0398000_12000.bin').read_bytes()
def root_return(mu,address,size,user):
 print('CHECK_RETURN',hex(address),hex(mu.reg_read(UC_ARM64_REG_X0)),flush=True)
for ins in Cs(CS_ARCH_ARM64,CS_MODE_ARM).disasm(rootbin[0x8a40:0x8e9c],0xd03a0a40):
 if ins.mnemonic=='bl':mu.hook_add(UC_HOOK_CODE,root_return,begin=ins.address+4,end=ins.address+4)
# Isolate decoder restoration from the app_process signature scan: the host
# has no Android app_process image. This is an explicit analysis-only bypass.
def skip_process_scan(mu,address,size,user):
 print('ANALYSIS_BYPASS app_process memory signature scan',flush=True)
 mu.reg_write(UC_ARM64_REG_X0,1);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR))
process_scan_signature=rootbin[0x4448:0x4448+48]
from checksum101 import checksum
def fast_checksum(mu,address,size,user):
 a,b,c,d=[mu.reg_read(r) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3]]
 data=bytes(mu.mem_read(a,d or b));value=checksum(data,b,c,d);print('CHECKSUM',hex(a),hex(b),hex(c),hex(d),hex(value),flush=True)
 mu.reg_write(UC_ARM64_REG_X0,value);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR))
checksum_signature=(ROOT / 'stage101_loader/executable_d0652000_17000.bin').read_bytes()[0x9a40:0x9a40+64]
report_signature=(ROOT / 'stage101_loader/executable_d0652000_17000.bin').read_bytes()[0x120b0:0x120b0+64]
# The following driver only performs runtime/debugger checks and clears x5
# on its normal success path. The offline harness has no ART runtime.
art_guard_signature=(ROOT / 'stage101_loader/executable_dba4a000_11000.bin').read_bytes()[0x47c0:0x47c0+48]
def skip_art_guard(mu,address,size,user):
 print('ANALYSIS_BYPASS ART runtime/debugger guard driver',hex(address),flush=True)
 flag=mu.reg_read(UC_ARM64_REG_X5)
 if flag:mu.mem_write(flag,b'\0')
 mu.reg_write(UC_ARM64_REG_X0,1);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR))
dump_guard_signature=(ROOT / 'stage101_loader/executable_dc0e7000_10000.bin').read_bytes()[0x4570:0x4570+48]
def skip_dump_guard(mu,address,size,user):
 print('ANALYSIS_BYPASS anti-dump IPC/watchdog driver',hex(address),flush=True)
 flag=mu.reg_read(UC_ARM64_REG_X5)
 if flag:mu.mem_write(flag,b'\0')
 mu.reg_write(UC_ARM64_REG_X0,1);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR))
fork_guard_signature=(ROOT / 'stage101_loader/executable_dc1fc000_b000.bin').read_bytes()[0x3128:0x3128+48]
def skip_fork_guard(mu,address,size,user):
 print('ANALYSIS_BYPASS fork-based guard driver',hex(address),flush=True)
 flag=mu.reg_read(UC_ARM64_REG_X5)
 if flag:mu.mem_write(flag,b'\0')
 mu.reg_write(UC_ARM64_REG_X0,1);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR))
helper_guard_signature=(ROOT / 'stage101_loader/executable_dc24f000_12000.bin').read_bytes()[0x3e58:0x3e58+48]
def skip_helper_guard(mu,address,size,user):
 print('ANALYSIS_BYPASS helper process launcher',hex(address),flush=True)
 flag=mu.reg_read(UC_ARM64_REG_X5)
 if flag:mu.mem_write(flag,b'\x01')
 mu.reg_write(UC_ARM64_REG_X0,1);mu.reg_write(UC_ARM64_REG_PC,mu.reg_read(UC_ARM64_REG_LR))
# Python-side memory access must honor the same lazy ELF mapping as emulated accesses.
raw_mem_read=mu.mem_read;raw_mem_write=mu.mem_write
def ensure_main(address,size):
 if BASE<=address and address+size<=BASE+0x187a0000:
  for page in range(address&~4095,(address+size+4095)&~4095,4096):
   if page not in mapped:map_page(page)
def safe_read(address,size):ensure_main(address,size);return raw_mem_read(address,size)
def safe_write(address,data):ensure_main(address,len(data));return raw_mem_write(address,data)
mu.mem_read=safe_read;mu.mem_write=safe_write
