"""Portable SNFS/SNMS extraction. All writes stay inside the selected output."""
from pathlib import Path, PurePosixPath
import hashlib, io, json, os, re, struct, subprocess, sys, time
import numpy as np
from PIL import Image
import texture2ddecoder as tex

ASSETS = Path(getattr(sys, '_MEIPASS', Path(__file__).parent)) / 'assets'
IMAGES = {'.png','.apng','.jpg','.jpeg','.bmp','.tga','.dds','.pkm','.pvr','.ktx'}
AUDIO = {'.ogg','.oga','.wav','.mp3','.aac','.flac'}
VIDEO = {'.rm5','.r5i','.mp4','.avi','.webm'}
NO_WINDOW = 0x08000000 if os.name == 'nt' else 0

class Cancelled(Exception): pass

def atomic(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + '.partial')
    tmp.write_bytes(data)
    os.replace(tmp, path)

def json_write(path, value):
    atomic(path, json.dumps(value, ensure_ascii=False, indent=2).encode('utf8'))

def safe_path(root, *parts):
    for part in parts:
        p = PurePosixPath(str(part).replace('\\','/'))
        if p.is_absolute() or any(s in ('.','..') or ':' in s for s in p.parts):
            raise ValueError('危険な出力パス: ' + str(part))
    dest = root.joinpath(*parts).resolve()
    if not dest.is_relative_to(root.resolve()): raise ValueError('出力先の範囲外')
    return dest

def lzss(b):
    if b[:4] != b'LZSS': raise ValueError('LZSS ヘッダー不正')
    packed, size, mode = struct.unpack_from('<III', b, 4)
    if size > 512*1024*1024 or packed > len(b) or packed < 16: raise ValueError('LZSS サイズ不正')
    if mode == 0:
        data = b[16:16+size]
        if len(data) != size: raise ValueError('LZSS データ不足')
        return data
    if mode != 4: raise ValueError(f'未対応 LZSS mode={mode}')
    i=16; out=bytearray()
    while len(out)<size:
        flag=b[i]; i+=1
        for bit in range(7,-1,-1):
            if len(out)==size: break
            if flag>>bit&1: out.append(b[i]); i+=1
            else:
                v=b[i]|b[i+1]<<8; i+=2; d=v>>3; n=v&7
                if n==7: n+=b[i]; i+=1
                n+=16 if d==0 else 3
                if len(out)+n>size: raise ValueError('LZSS 展開サイズ超過')
                if not d: out.extend(b[i:i+n]); i+=n
                else:
                    if d>len(out): raise ValueError('LZSS 参照位置不正')
                    if d>=n: out.extend(out[len(out)-d:len(out)-d+n])
                    else:
                        for _ in range(n): out.append(out[-d])
            if i>packed: raise ValueError('LZSS データ不足')
    if i!=packed: raise ValueError('LZSS 終端不一致')
    return bytes(out)

def cpt(raw, name):
    tab=(ASSETS/'cpt_table.bin').read_bytes()
    seed=ord(name[0])*61+ord(name[1])*49
    state=((((seed*214013+0x3b3cc87b)&0xffffffff)>>16)&0x7fff)+seed
    out=bytearray(raw)
    for i in range(min(256,len(raw))):
        a=(state*214013+2531011)&0xffffffff; c=(a*214013+2531011)&0xffffffff
        state=(c*214013+2531011)&0xffffffff
        out[i]=((raw[i]-(c>>16))^(a>>16)^tab[(state>>16)&255])&255
    return bytes(out)

def xor(data,key):
    return np.bitwise_xor(np.frombuffer(data,np.uint8),np.resize(np.frombuffer(key,np.uint8),len(data))).tobytes()

def read_range(path, offset, size):
    if offset<0 or size<0 or size>512*1024*1024 or offset+size>path.stat().st_size:
        raise ValueError('PB内の位置またはサイズが不正: '+str(path))
    with path.open('rb') as f: f.seek(offset); return f.read(size)

def catalog(first, base):
    prefix=first.stem[:-2]
    with first.open('rb') as f: f.seek(-16,2); last,off,n,ver=struct.unpack('<4I',f.read(16))
    cat=lzss(read_range(first.parent/f'{prefix}{last:02d}.pb',off,n))
    rows=[]; pos=0
    def string(offset, end):
        raw=cat[offset:cat.index(0,offset,end)]
        try:return raw.decode('utf8')
        except UnicodeDecodeError:return raw.decode('cp932')
    while cat[pos+4:pos+8]==b'INAM':
        size,count,stride=struct.unpack_from('<I4xII',cat,pos)
        if size<20 or pos+size>len(cat) or stride!=20: raise ValueError('INAM構造不正')
        fs,rs=cat[pos+18:pos+20];folder=string(pos+fs,pos+size)
        if rs+count*20>size:raise ValueError('INAM項目数不正')
        for i in range(count):
            pack,offset,length,unpacked,no=struct.unpack_from('<5I',cat,pos+rs+20*i)
            name=string(pos+no,pos+size)
            rows.append(dict(group=str(first.parent.relative_to(base)),prefix=prefix,folder=folder,name=name,
                             pack=pack,offset=offset,size=length,unpacked_size=unpacked,
                             source=str(first.parent/f'{prefix}{pack:02d}.pb')))
        pos+=size
    if cat[pos+4:pos+8]!=b'IEND': raise ValueError('カタログ終端不正')
    return rows

def scan(root, cancel=None):
    root=Path(root).resolve(); rows=[];errors=[]
    firsts=sorted(p for p in root.rglob('*.pb') if re.fullmatch(r'sn(?:fs|ms)00',p.stem,re.I))
    if not firsts:raise ValueError('snfs00.pb / snms00.pb が見つかりません。PB一式のフォルダを選択してください。')
    for p in firsts:
        if cancel and cancel.is_set():raise Cancelled()
        try:rows.extend(catalog(p,root))
        except Exception as ex:errors.append(dict(source=str(p),error=str(ex)))
    return rows,errors

def recognized(b,ext):
    if b.startswith((b'OggS',b'RM5 ',b'LZSS',b'\x89PNG\r\n\x1a\n',b'DDS ',b'PKM ',b'PVA ',b'PVR\x03',b'\xabKTX',b'RIFF',b'fLaC',b'ID3',b'BM',b'\xff\xd8\xff')):return True
    if len(b)>12 and b[4:8]==b'ftyp':return True
    if len(b)>=52 and b[44:48]==b'PVR!':return True
    if ext in ('.txt','.json','.html','.xml','.csv'):
        try:
            text=b.decode('utf8')
            if text and all(c.isprintable() or c in '\r\n\t' for c in text):return True
        except UnicodeDecodeError:pass
    if ext=='.tga' and len(b)>=18:
        w,h=struct.unpack_from('<HH',b,12)
        return b[1]==0 and b[2] in (2,3,10,11) and 0<w<=8192 and 0<h<=8192 and b[16] in (8,16,24,32)
    return False

class Decoder:
    def __init__(self, custom=''):
        self.keys={p.stem:p.read_bytes() for p in sorted((ASSETS/'keys').glob('*.bin'))}
        if custom:
            k=Path(custom).read_bytes()
            if len(k)!=65536:raise ValueError('追加XOR鍵は65,536バイト必要です')
            self.keys={'custom':k,**self.keys}
    def learn_ogg(self, raw):
        if raw.startswith(b'OggS'):return
        known=b'OggS\0\x02'+bytes(8)
        head=bytes(a^b for a,b in zip(raw[:14],known))
        if len(head)!=14 or max(head)>127:return
        if any(k[:14]==head for k in self.keys.values()):return
        # MSVC LCG key: output current state high seven bits, then advance.
        states=np.arange(1<<24,dtype=np.uint32)|(head[0]<<24)
        initial=states.copy()
        for v in head[1:]:
            states=states*np.uint32(214013)+np.uint32(2531011)
            mask=((states>>24)&127)==v;states=states[mask];initial=initial[mask]
            if not len(states):return
        if len(initial)==1:
            state=int(initial[0]);key=bytearray()
            for _ in range(65536):
                key.append((state>>24)&127);state=(state*214013+2531011)&0xffffffff
            self.keys['auto_'+str(int(initial[0]))]=bytes(key)
    def decrypt(self, raw, row):
        ext=Path(row['name']).suffix.lower()
        if ext in ('.ogg','.oga'):self.learn_ogg(raw)
        candidates=[('plain',raw),('cpt',cpt(raw,row['name']))]
        for name,k in self.keys.items():
            head=xor(raw[:64],k)
            if recognized(head,ext): candidates.append(('xor:'+name,xor(raw,k)))
        for method,b in candidates:
            if b.startswith(b'LZSS'):
                try:return lzss(b),method+'+lzss'
                except (ValueError,IndexError):continue
            if recognized(b,ext):return b,method
        raise ValueError('未対応の暗号化方式または形式（追加XOR鍵を指定可能）')

def image_decode(b):
    alpha=None
    if b.startswith(b'PVA '):
        st,en,aw,ah=struct.unpack_from('<4I',b,4);alpha=b[en:]
        if len(alpha)!=aw*ah:raise ValueError('PVA alphaサイズ不正')
        b=b[st:en]
    if len(b)>=52 and b[44:48]==b'PVR!':
        header,h,w,mips,flags,n,bpp,rm,gm,bm,am,magic,surfaces=struct.unpack_from('<13I',b)
        if flags&255 not in (24,25) or surfaces!=1:raise ValueError('未対応PVR v2形式')
        im=Image.frombytes('RGBA',(w,h),tex.decode_pvrtc(b[header:header+n],w,h,(flags&255)==24),'raw','BGRA')
    elif b.startswith(b'PVR\x03'):
        ver,flags,pf,col,ct,h,w,dep,surf,face,mip,meta=struct.unpack_from('<IIQ9I',b)
        if dep!=1 or surf!=1 or face!=1:raise ValueError('未対応PVR配列')
        data=b[52+meta:]
        if pf in (0,1,2,3):pixels=tex.decode_pvrtc(data,w,h,pf in (0,1))
        elif pf==6:pixels=tex.decode_etc1(data,w,h)
        else:raise ValueError('未対応PVR pixel format '+str(pf))
        im=Image.frombytes('RGBA',(w,h),pixels,'raw','BGRA')
    elif b.startswith((b'PKM 10',b'PKM 11',b'PKM 20')):
        fmt,ew,eh,w,h=struct.unpack_from('>5H',b,6)
        if not (0<w<=ew<=16384 and 0<h<=eh<=16384 and ew%4==eh%4==0):raise ValueError('PKM寸法不正')
        funcs={0:tex.decode_etc1,1:tex.decode_etc2,3:tex.decode_etc2a8,4:tex.decode_etc2a1}
        if fmt not in funcs or len(b)!=16+(ew//4)*(eh//4)*(16 if fmt==3 else 8):raise ValueError('PKM形式・長さ不正')
        im=Image.frombytes('RGBA',(ew,eh),funcs[fmt](b[16:],ew,eh),'raw','BGRA').crop((0,0,w,h))
        if b[:6]==b'PKM 11':
            if fmt!=0 or h%2:raise ValueError('PKM11 alpha形式不正')
            a=im.crop((0,h//2,w,h)).getchannel('R'); im=im.crop((0,0,w,h//2));im.putalpha(a)
    elif b.startswith(b'\xabKTX 11'):
        end,typ,ts,fmt,internal,base,w,h,dep,arr,faces,mips,meta=struct.unpack_from('<13I',b,12)
        if end!=0x04030201 or dep!=0 or arr!=0 or faces!=1:raise ValueError('未対応KTX配列')
        pos=64+meta;n=struct.unpack_from('<I',b,pos)[0];data=b[pos+4:pos+4+n]
        funcs={0x9278:tex.decode_etc2a8,0x9274:tex.decode_etc2,0x9276:tex.decode_etc2a1,0x8d64:tex.decode_etc1}
        if internal in funcs:im=Image.frombytes('RGBA',(w,h),funcs[internal](data,w,h),'raw','BGRA')
        elif typ==0x1401 and fmt in (0x1907,0x1908):im=Image.frombytes('RGBA' if fmt==0x1908 else 'RGB',(w,h),data)
        else:raise ValueError('未対応KTX '+hex(internal))
    elif b.startswith(b'DDS ') and b[84:88]==b'ETC ':
        h,w=struct.unpack_from('<II',b,12)
        im=Image.frombytes('RGBA',(w,h),tex.decode_etc1(b[128:],w,h),'raw','BGRA')
    else:
        im=Image.open(io.BytesIO(b));im.load()
    if alpha is not None:
        if im.size!=(aw,ah):raise ValueError('PVA寸法不一致')
        im.putalpha(Image.frombytes('L',(aw,ah),alpha))
    return im

CRC_TABLE=[]
for _i in range(256):
    _r=_i<<24
    for _ in range(8):_r=((_r<<1)^ (0x04c11db7 if _r&0x80000000 else 0))&0xffffffff
    CRC_TABLE.append(_r)

def ogg_streams(b):
    """Validate CRC and split chained logical streams; exclude only trailing padding."""
    pos=0;start=0;serial=None;seq=0;parts=[];eos=False
    while pos+27<=len(b) and b[pos:pos+5]==b'OggS\0':
        n=b[pos+26];end=pos+27+n+sum(b[pos+27:pos+27+n])
        if end>len(b):raise ValueError('Oggページが途中で終了')
        page=bytearray(b[pos:end]);stored=struct.unpack_from('<I',page,22)[0];page[22:26]=bytes(4);crc=0
        for v in page:crc=((crc<<8)&0xffffffff)^CRC_TABLE[((crc>>24)^v)&255]
        if crc!=stored:raise ValueError(f'Ogg CRC不一致 offset={pos}')
        ser,sq=struct.unpack_from('<II',b,pos+14);flags=b[pos+5]
        if serial is None:
            if not flags&2 or sq!=0:raise ValueError('Ogg開始ページ不正')
            serial=ser;seq=0;start=pos;eos=False
        if ser!=serial or sq!=seq:raise ValueError('Oggページ順序不正')
        seq+=1;pos=end
        if flags&4:parts.append(b[start:pos]);serial=None;eos=True
    if not parts or not eos or serial is not None:raise ValueError('Ogg終端ページ不足')
    tail=b[pos:]
    if tail and any(tail):raise ValueError('Oggの後ろに未識別データあり（自動削除しません）')
    return parts,len(tail)

def subprocess_checked(args,cancel,logfile,timeout=3600):
    with logfile.open('wb') as log:
        p=subprocess.Popen(args,stdout=log,stderr=subprocess.STDOUT,creationflags=NO_WINDOW)
        start=time.monotonic()
        try:
            while p.poll() is None:
                if cancel.wait(.15):raise Cancelled()
                if time.monotonic()-start>timeout:raise TimeoutError('処理時間の上限を超えました')
            if p.returncode:raise RuntimeError(f'補助処理の終了コード {p.returncode}: '+logfile.read_text('utf8',errors='replace')[-1600:])
        finally:
            if p.poll() is None:
                # Kill decoder and its ffmpeg child together on cancellation.
                if os.name=='nt':subprocess.run(['taskkill','/PID',str(p.pid),'/T','/F'],capture_output=True,creationflags=NO_WINDOW)
                else:p.kill()
                p.wait()

def run(root, output, options, cancel, emit, custom='', limit=0):
    root=Path(root).resolve();out=Path(output).resolve()
    if out==root or root.is_relative_to(out):raise ValueError('入力フォルダやその親を出力先には指定できません')
    out.mkdir(parents=True,exist_ok=True)
    emit('log','カタログを読み込んでいます…')
    rows,scan_errors=scan(root,cancel);json_write(out/'catalog.json',rows)
    selected=[x for x in rows if options['raw'] or (options['images'] and Path(x['name']).suffix.lower() in IMAGES) or (options['audio'] and Path(x['name']).suffix.lower() in AUDIO) or (options['video'] and Path(x['name']).suffix.lower() in VIDEO)]
    if limit:selected=selected[:limit]
    emit('log',f'カタログ {len(rows):,}件 / 処理対象 {len(selected):,}件')
    decoder=Decoder(custom);results=[];counts={'ok':0,'failed':0,'skipped':0};seen=set();cancelled=False
    # Learn each pack group's audio key before processing its movies/images.
    learned=set()
    for row in rows:
        group=(row['group'],row['prefix'])
        if group not in learned and Path(row['name']).suffix.lower()=='.ogg':
            if cancel.is_set():raise Cancelled()
            try:decoder.learn_ogg(read_range(Path(row['source']),row['offset'],min(64,row['size'])))
            except (OSError,ValueError):pass
            learned.add(group)
    with (out/'manifest.jsonl').open('w',encoding='utf8') as journal:
        for idx,row in enumerate(selected):
            if cancel.is_set():cancelled=True;break
            record=dict(row); paths=[]
            try:
                rel=Path(row['group'])/row['prefix']/row['folder']/row['name']
                target=safe_path(out,str(rel));identity=str(target).casefold()
                if identity in seen:raise ValueError('カタログ内の出力名が重複しています')
                seen.add(identity)
                source=Path(row['source']);stat=source.stat()
                signature=hashlib.sha256(json.dumps([str(root),row,stat.st_size,stat.st_mtime_ns,options,custom,hashlib.sha256(Path(custom).read_bytes()).hexdigest() if custom else '',3],sort_keys=True).encode()).hexdigest()
                receipt=safe_path(out,'_state',signature+'.json')
                if options['resume'] and receipt.exists():
                    old=json.loads(receipt.read_text('utf8'))
                    if old['outputs'] and all(safe_path(out,x['path']).is_file() and hashlib.sha256(safe_path(out,x['path']).read_bytes()).hexdigest()==x['sha256'] for x in old['outputs']):
                        record.update(status='skipped',outputs=old['outputs']);counts['skipped']+=1
                        journal.write(json.dumps(record,ensure_ascii=False)+'\n');results.append(record)
                        emit('progress',(idx+1,len(selected),counts,row['name']));continue
                raw=read_range(source,row['offset'],row['size']);b,method=decoder.decrypt(raw,row)
                record['method']=method;ext=Path(row['name']).suffix.lower()
                if options['raw']:
                    p=safe_path(out,'decrypted',str(rel));atomic(p,b);paths.append(p)
                if options['images'] and ext in IMAGES:
                    im=image_decode(b);buf=io.BytesIO();im.save(buf,format='PNG',compress_level=3)
                    p=safe_path(out,'images',str(rel)+'.png');atomic(p,buf.getvalue())
                    with Image.open(p) as test:test.load()
                    paths.append(p)
                    if getattr(im,'n_frames',1)>1:
                        p=safe_path(out,'animations',str(rel));atomic(p,b);paths.append(p)
                if options['audio'] and ext in AUDIO:
                    parts,padding=ogg_streams(b) if b.startswith(b'OggS') else ([b],0)
                    record['removed_zero_padding']=padding
                    for i,part in enumerate(parts):
                        name=str(rel) if len(parts)==1 else str(rel.with_name(rel.stem+f'_part{i+1:02d}'+rel.suffix))
                        p=safe_path(out,'audio',name);atomic(p,part)
                        log=safe_path(out,'_logs','audio_check.log')
                        log.parent.mkdir(exist_ok=True)
                        subprocess_checked([str(ASSETS/'ffmpeg.exe'),'-nostdin','-v','error','-xerror','-i',str(p),'-f','null','-'],cancel,log,600)
                        paths.append(p)
                if options['video'] and ext in VIDEO:
                    name=str(rel)+'.rm5' if ext=='.r5i' else str(rel)
                    p=safe_path(out,'video',name)
                    if ext in ('.rm5','.r5i'):
                        if b[:4]!=b'RM5 ' or len(b)<36:raise ValueError('RM5ヘッダー不正')
                        h,w=struct.unpack_from('>HH',b,16);frames=struct.unpack_from('>I',b,20)[0]
                        if not (0<w<=8192 and 0<h<=8192 and frames>0):raise ValueError('RM5寸法・フレーム数不正')
                        record.update(width=w,height=h,frames=frames)
                    atomic(p,b);paths.append(p)
                    if options['mp4'] and ext in ('.rm5','.r5i'):
                        mp4=safe_path(out,'mp4',str(rel)+'.mp4');mp4.parent.mkdir(parents=True,exist_ok=True)
                        log=safe_path(out,'_logs',signature+'.log');log.parent.mkdir(exist_ok=True)
                        cmd=([str(Path(sys.executable).parent/'PBVideoWorker.exe')] if getattr(sys,'frozen',False) else [sys.executable,str(Path(__file__).parent/'video_worker.py')])+[str(p),str(mp4)]
                        emit('log','MP4変換中: '+row['name'])
                        subprocess_checked(cmd,cancel,log,86400)
                        meta=json.loads(mp4.with_suffix('.json').read_text('utf8'))
                        if not mp4.is_file() or not meta.get('validated') or meta.get('color_pipeline_version')!=2:
                            raise ValueError('MP4の検証済み出力が見つかりません')
                        paths.extend([mp4,mp4.with_suffix('.json')])
                if not paths:raise ValueError('選択した形式に該当しません')
                outputs=[dict(path=str(p.relative_to(out)),sha256=hashlib.sha256(p.read_bytes()).hexdigest(),size=p.stat().st_size) for p in paths]
                record.update(status='ok',outputs=outputs);json_write(receipt,record);counts['ok']+=1
            except Cancelled:cancelled=True;break
            except Exception as ex:
                record.update(status='failed',error=str(ex),partial_outputs=[str(p.relative_to(out)) for p in paths]);counts['failed']+=1
                emit('log','失敗: '+row['name']+' — '+str(ex))
            results.append(record);journal.write(json.dumps(record,ensure_ascii=False)+'\n');journal.flush()
            emit('progress',(idx+1,len(selected),dict(counts),row['name']))
    failures=scan_errors+[x for x in results if x['status']=='failed'];json_write(out/'failures.json',failures)
    summary=dict(status='cancelled' if cancelled else ('complete_with_failures' if failures else 'complete'),total=len(selected),processed=len(results),**counts,catalog_errors=len(scan_errors),output=str(out))
    json_write(out/'summary.json',summary);return summary
