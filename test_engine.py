import unittest, threading, json, struct
from pathlib import Path
from engine import *

BASE=Path(__file__).parent/'test-output'

def make_fixture():
    sources=[(r'D:\fever2_work\a0123',['psg2_no_inf01_com_base_00_000_f_a.pkm','debug_arrow_left.tga','ui_button.dds','0001.ogg']),
             (r'D:\twin_angel_work\cdn_dl\1.0.0',['190_dem_info_menu_onryou.rm5','case_01.pvr']),
             (r'D:\gandam_work\files\a0154',['ball.ktx'])]
    chunks=[];entries=[];offset=0
    for root,names in sources:
        rows,errors=scan(root)
        assert not errors
        for name in names:
            row=next(x for x in rows if x['name']==name)
            raw=read_range(Path(row['source']),row['offset'],row['size'])
            entries.append((name,offset,len(raw),row['unpacked_size']));chunks.append(raw);offset+=len(raw)
    folder=b'fixture/\0';rs=20+len(folder);strings=bytearray();records=bytearray()
    for name,off,n,unpacked in entries:
        records.extend(struct.pack('<5I',0,off,n,unpacked,rs+20*len(entries)+len(strings)))
        strings.extend(name.encode()+b'\0')
    size=rs+len(records)+len(strings)
    cat=struct.pack('<I4sIIHBB',size,b'INAM',len(entries),20,0,20,rs)+folder+records+strings+struct.pack('<I4sI',12,b'IEND',0)
    packed=b'LZSS'+struct.pack('<III',16+len(cat),len(cat),0)+cat
    dest=BASE/'fixture';dest.mkdir(parents=True,exist_ok=True)
    (dest/'snfs00.pb').write_bytes(b''.join(chunks)+packed+struct.pack('<4I',0,offset,len(packed),1))
    return dest,len(entries)

class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):cls.fixture,cls.n=make_fixture()
    def test_01_extract_resume_and_repair(self):
        opt=dict(raw=True,images=True,audio=True,video=True,mp4=False,resume=True)
        out=BASE/'fixture-extract';event=threading.Event()
        result=run(self.fixture,out,opt,event,lambda *_:None)
        self.assertEqual(result['failed'],0);self.assertEqual(result['processed'],self.n)
        result=run(self.fixture,out,opt,event,lambda *_:None);self.assertEqual(result['skipped'],self.n)
        png=next((out/'images').rglob('*.png'));png.write_bytes(b'corrupt')
        result=run(self.fixture,out,opt,event,lambda *_:None)
        self.assertEqual(result['ok'],1);self.assertEqual(result['skipped'],self.n-1)
        with Image.open(png) as im:im.load()
    def test_02_cancel(self):
        event=threading.Event()
        def emit(kind,value):
            if kind=='progress':event.set()
        opt=dict(raw=True,images=False,audio=False,video=False,mp4=False,resume=False)
        result=run(self.fixture,BASE/'cancel',opt,event,emit)
        self.assertEqual(result['status'],'cancelled');self.assertEqual(result['processed'],1)
    def test_03_reject_escape_and_truncated(self):
        for part in ['../escape','C:/escape','/absolute','folder/../../escape']:
            with self.assertRaises(ValueError):safe_path(BASE,part)
        with self.assertRaises((ValueError,IndexError,struct.error)):lzss(b'LZSS'+struct.pack('<III',19,50,4)+b'\xff\x00\x00')
    def test_04_ogg_corruption(self):
        rows,_=scan(self.fixture);row=next(x for x in rows if x['name']=='0001.ogg')
        raw=read_range(Path(row['source']),row['offset'],row['size']);b,_=Decoder().decrypt(raw,row)
        ogg_streams(b)
        with self.assertRaises(ValueError):ogg_streams(b[:-1]+bytes([b[-1]^1]))
    def test_05_alpha(self):
        rows,_=scan(self.fixture);row=next(x for x in rows if x['name'].endswith('.pkm'))
        b,_=Decoder().decrypt(read_range(Path(row['source']),row['offset'],row['size']),row)
        self.assertEqual(b[:6],b'PKM 11');im=image_decode(b)
        self.assertEqual(im.size,(128,64));self.assertNotEqual(im.getchannel('A').getextrema(),(255,255))

if __name__=='__main__':unittest.main(verbosity=2)
