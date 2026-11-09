"""Use the recovered ARM64 RM5 decoder; fail closed on decoding/encoding errors."""
import argparse,json,struct,subprocess,time,os,hashlib
from pathlib import Path
from rm5_native import alloc,call,mu,ROOT,OUT
import numpy as np
from engine import ASSETS, NO_WINDOW
from PIL import Image
parser=argparse.ArgumentParser();parser.add_argument('source');parser.add_argument('output');parser.add_argument('--preview');args=parser.parse_args()
source=Path(args.source);output=Path(args.output);output.parent.mkdir(parents=True,exist_ok=True)
started=time.monotonic();raw=source.read_bytes();data=alloc(len(raw));mu.mem_write(data,raw);handle=alloc(4096)
def checked(name,*values):
 result=call(name,*values)
 if result:raise RuntimeError(name+' returned '+hex(result))
checked('rm5CreateMemDecoder',handle,data,len(raw),0);decoder=struct.unpack('<Q',bytes(mu.mem_read(handle,8)))[0]
info=alloc(4096);checked('rm5GetMovieInfo',decoder,info,3)
width,height,fmt,frames,streams,fpsnum,fpsden,flags=struct.unpack('<8I',bytes(mu.mem_read(info,32)))
assert 0<width<=8192 and 0<height<=8192 and frames>0 and fpsnum>0 and fpsden>0
pixels=alloc(width*height*4);temporary=output.with_name(output.stem+'.partial.mp4')
cmd=[str(ASSETS/'ffmpeg.exe'),'-hide_banner','-loglevel','error','-y','-f','rawvideo','-pixel_format','rgb24','-video_size',f'{width}x{height}','-framerate',f'{fpsnum}/{fpsden}','-i','pipe:0','-an','-vf','pad=ceil(iw/2)*2:ceil(ih/2)*2:0:0:black','-c:v','libx264','-threads','1','-preset','fast','-crf','18','-pix_fmt','yuv420p','-movflags','+faststart',str(temporary)]
process=subprocess.Popen(cmd,stdin=subprocess.PIPE,stderr=subprocess.PIPE,creationflags=NO_WINDOW)
try:
 for frame in range(frames):
  checked('rm5Decode',decoder,frame);checked('rm5GetImage',decoder,pixels,width*height*4,0,width*4)
  rawpixels=bytes(mu.mem_read(pixels,width*height*4))
  if args.preview and frame in [0,frames//2,frames-1]:
   pp=Path(args.preview);pp.mkdir(parents=True,exist_ok=True);Image.frombytes('RGBA',(width,height),rawpixels,'raw','RGBA').save(pp/f'{source.stem}_{frame:05d}.png')
  rgba=np.frombuffer(rawpixels,np.uint8).reshape(height,width,4)
  rgb=((rgba[:,:,:3].astype(np.uint16)*rgba[:,:,3:4].astype(np.uint16)+127)//255).astype(np.uint8)
  process.stdin.write(rgb.tobytes())
  if frame%100==0:print('PROGRESS',source.name,frame,frames,flush=True)
 process.stdin.close();error=process.stderr.read().decode(errors='replace');returncode=process.wait()
 if returncode:raise RuntimeError('ffmpeg: '+error)
 probe=subprocess.run([str(ASSETS/'ffprobe.exe'),'-v','error','-count_frames','-select_streams','v:0','-show_entries','stream=width,height,nb_read_frames,r_frame_rate','-of','json',str(temporary)],capture_output=True,text=True,check=True,creationflags=NO_WINDOW)
 stream=json.loads(probe.stdout)['streams'][0]
 if int(stream['nb_read_frames'])!=frames:raise RuntimeError('encoded frame count mismatch')
 os.replace(temporary,output)
 record=dict(color_pipeline_version=2,decoder_pixel_format='RGBA',source_sha256=hashlib.sha256(raw).hexdigest(),source=str(source),output=str(output),width=width,height=height,encoded_width=stream['width'],encoded_height=stream['height'],frames=frames,fps_numerator=fpsnum,fps_denominator=fpsden,seconds=round(time.monotonic()-started,3),alpha_background='black',audio=False,validated=True)
 output.with_suffix('.json').write_text(json.dumps(record,ensure_ascii=False,indent=2),encoding='utf8');print('COMPLETE',json.dumps(record,ensure_ascii=False),flush=True)
finally:
 if process.poll() is None:process.kill();process.wait()
