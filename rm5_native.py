from rm5_runtime import *
import json,time
heap_next[0]=0x100000000
symbols=json.loads((ROOT/'restored_symbols.json').read_text())
for page in sorted(mapped):mu.mem_unmap(page,4096)
mapped.clear()
for lo,hi,offset in [(0,0x3e51000,0),(0x3e61000,0x462b000,0x3e518e0-0x3e618e0+0x3e61000)]:
 mu.mem_map(BASE+lo,hi-lo);mapped.update(range(BASE+lo,BASE+hi,4096));mu.mem_write(BASE+lo,ELF[offset:offset+hi-lo])
for base in [0xdc385000,0xdd60c000,0xdd60e000,0xdd618000,0xdd61a000,0xdd61c000]:
 raw=(ROOT/f'stage101_loader/heap_{base:x}.bin').read_bytes();mu.mem_map(base,len(raw));mu.mem_write(base,raw)
bss=(ROOT/'bss_pages.bin').read_bytes()
for off in range(0,len(bss),4104):
 page=struct.unpack_from('<Q',bss,off)[0];map_page(page);mu.mem_write(page,bss[off+8:off+4104])
mu.reg_write(UC_ARM64_REG_TPIDR_EL0,STACK+0x8000)
byname={v.split(':',1)[1]:k for k,v in imports.items()}
regs=[UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3,UC_ARM64_REG_X4,UC_ARM64_REG_X5,UC_ARM64_REG_X6,UC_ARM64_REG_X7]
def alloc(size):
 p=heap_next[0];span=(size+4095)&~4095;heap_next[0]+=span+4096;mu.mem_map(p,span);allocations[p]=size;return p

def call(name,*args):
 addr=BASE+symbols[name]['value'] if isinstance(name,str) else name
 mu.reg_write(UC_ARM64_REG_SP,STACK+STACK_SZ-0x10000);mu.reg_write(UC_ARM64_REG_LR,RET)
 for r,v in zip(regs,list(args)+[0]*(8-len(args))):mu.reg_write(r,v)
 next_pc=addr;start=time.monotonic()
 for turn in range(1000):
  try:mu.emu_start(next_pc,RET,timeout=30_000_000,count=0)
  except Exception:
   import traceback;traceback.print_exc();raise RuntimeError('native PC '+hex(mu.reg_read(UC_ARM64_REG_PC)))
  if pending_threads:
   tid,ctx=pending_threads.pop();thread_frames.append((tid,ctx));job=thread_jobs[tid];threadstack=0x7d00000000+len(thread_frames)*0x1000000
   if threadstack not in thread_stacks:mu.mem_map(threadstack,0x800000);thread_stacks.add(threadstack)
   mu.reg_write(UC_ARM64_REG_SP,threadstack+0x7f0000);mu.reg_write(UC_ARM64_REG_X0,job['arg']);mu.reg_write(UC_ARM64_REG_LR,RET);next_pc=job['entry'];continue
  if mu.reg_read(UC_ARM64_REG_PC)==RET and thread_frames:
   tid,ctx=thread_frames.pop();thread_jobs[tid].update(done=True,result=mu.reg_read(UC_ARM64_REG_X0));mu.context_restore(ctx);next_pc=mu.reg_read(UC_ARM64_REG_PC);continue
  if mu.reg_read(UC_ARM64_REG_PC)==RET:break
  raise RuntimeError('stopped '+str(name)+' PC '+hex(mu.reg_read(UC_ARM64_REG_PC)))
 result=mu.reg_read(UC_ARM64_REG_X0)
 if name not in ['rm5Decode','rm5GetImage']:print('CALL',name,hex(result),'seconds',round(time.monotonic()-start,3),flush=True)
 return result
decode_blocks=deque(maxlen=12)
def decode_block(mu,address,size,user):decode_blocks.append((hex(address),[hex(mu.reg_read(r)) for r in regs]))
if '--trace' in sys.argv:mu.hook_add(UC_HOOK_BLOCK,decode_block,begin=BASE+0x14d5000,end=BASE+0x14ef000)
def exception_trace(mu,address,size,user):
 print('DECODE_BLOCKS',list(decode_blocks),flush=True)
 a=mu.reg_read(UC_ARM64_REG_X0);print('CPP_EXCEPTION',hex(mu.reg_read(UC_ARM64_REG_LR)),hex(a),bytes(mu.mem_read(a,16)).hex(),[hex(mu.reg_read(r)) for r in regs[1:4]],flush=True)
def entropy_trace(mu,address,size,user):
 if address==BASE+0x14e20c4 and mu.reg_read(UC_ARM64_REG_W23)<=8:return
 print('ENTROPY',hex(address),[(r,hex(mu.reg_read(r))) for r in [UC_ARM64_REG_X0,UC_ARM64_REG_X8,UC_ARM64_REG_X19,UC_ARM64_REG_X20,UC_ARM64_REG_X21,UC_ARM64_REG_X23,UC_ARM64_REG_X27]],flush=True)
if '--trace' in sys.argv:mu.hook_add(UC_HOOK_CODE,entropy_trace,begin=BASE+0x14e16e8,end=BASE+0x14e16e8)
addr=BASE+symbols['__cxa_throw']['value'];mu.hook_add(UC_HOOK_CODE,exception_trace,begin=addr,end=addr)
