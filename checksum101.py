from pathlib import Path
import numpy as np

def checksum(data,total,start=0,end=0):
 end=(end or total)//4;start//=4;a=total&0xffffffff if start==0 else 0;b=0
 words=np.frombuffer(data,dtype='<u4')
 for low in range(start,end,262144):
  high=min(end,low+262144);w=words[low:high];idx=np.arange(low,high,dtype=np.uint32);aa=0;bb=0
  for mod,left,group in [(13,False,0),(17,False,0),(29,True,0),(19,False,1),(23,False,1),(31,True,1)]:
   s=idx%mod;r=((w<<s)|(w>>(32-s))) if left else ((w>>s)|(w<<(32-s)))
   val=int(r.sum(dtype=np.uint64))
   if group==0:aa+=val
   else:bb+=val
  a=(a+aa)&0xffffffff;b=(b+bb)&0xffffffff
 return a^b

if __name__=='__main__':
 from unicorn import *
 from unicorn.arm64_const import *
 import random
 base=0xd0652000;code=Path('work/twin_video/stage101_loader/executable_d0652000_17000.bin').read_bytes();m=Uc(UC_ARCH_ARM64,UC_MODE_ARM);m.mem_map(base,0x20000);m.mem_write(base,code);m.mem_map(0x10000000,0x20000);m.mem_map(0x20000000,0x20000)
 data=random.Random(123).randbytes(4096);m.mem_write(0x10000000,data)
 for total,start,end in [(4096,0,0),(4096,64,0),(4096,0,64),(4096,20,128),(4096,4096,4096)]:
  m.reg_write(UC_ARM64_REG_SP,0x20010000);m.reg_write(UC_ARM64_REG_LR,0x20001000)
  for r,v in zip([UC_ARM64_REG_X0,UC_ARM64_REG_X1,UC_ARM64_REG_X2,UC_ARM64_REG_X3],[0x10000000,total,start,end]):m.reg_write(r,v)
  m.emu_start(base+0x9a40,0x20001000,count=1000000);actual=m.reg_read(UC_ARM64_REG_X0);expected=checksum(data,total,start,end);assert actual==expected,(actual,expected);print(total,start,end,hex(actual),'PASS')
