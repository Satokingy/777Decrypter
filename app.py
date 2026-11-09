import sys, os, json, threading, queue, traceback
from pathlib import Path

def main():
    for stream in (sys.stdout,sys.stderr):
        if stream and hasattr(stream,'reconfigure'):stream.reconfigure(encoding='utf8',errors='replace')
    if '--convert-video' in sys.argv:
        sys.argv=[sys.argv[0]]+sys.argv[sys.argv.index('--convert-video')+1:]
        if getattr(sys,'frozen',False):
            import subprocess
            sys.exit(subprocess.run([str(Path(sys.executable).parent/'PBVideoWorker.exe')]+sys.argv[1:],creationflags=0x08000000).returncode)
        if sys.stdout is None:
            sys.stdout=sys.stderr=open(str(sys.argv[2])+'.decoder.log','w',encoding='utf8',buffering=1)
        import convert_rm5
        return
    if '--cli' in sys.argv:
        import argparse
        from engine import run
        p=argparse.ArgumentParser();p.add_argument('--cli',action='store_true');p.add_argument('input');p.add_argument('output')
        p.add_argument('--types',default='images,audio,video');p.add_argument('--mp4',action='store_true');p.add_argument('--limit',type=int,default=0)
        a=p.parse_args();options={k:k in a.types.split(',') for k in ['raw','images','audio','video']};options.update(resume=True,mp4=a.mp4)
        result=run(a.input,a.output,options,threading.Event(),lambda k,v:print(k,v,flush=True),limit=a.limit)
        print(json.dumps(result,ensure_ascii=False),flush=True)
        sys.exit(0 if result['status']=='complete' else 1)
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox
    from tkinter.scrolledtext import ScrolledText
    from engine import run, scan, Cancelled, IMAGES, AUDIO, VIDEO
    app=tk.Tk();app.title('PB Asset Tool — 復号・画像・音声・動画抽出');app.geometry('900x720');app.minsize(760,610)
    style=ttk.Style(app);style.theme_use('vista' if 'vista' in style.theme_names() else 'clam')
    style.configure('.',font=('Yu Gothic UI',10));style.configure('Title.TLabel',font=('Yu Gothic UI',19,'bold'))
    root=ttk.Frame(app,padding=22);root.pack(fill='both',expand=True)
    ttk.Label(root,text='PB Asset Tool',style='Title.TLabel').pack(anchor='w')
    ttk.Label(root,text='PB一式から、元の名前でアセットを取り出します。',padding=(0,4,0,16)).pack(anchor='w')
    source=tk.StringVar();output=tk.StringVar();key=tk.StringVar();busy=[False];events=queue.Queue();cancel=threading.Event();controls=[]
    def pick(var,is_input=False,is_key=False):
        value=filedialog.askopenfilename(title='65,536バイトのXOR鍵',filetypes=[('Binary','*.bin'),('All','*')]) if is_key else filedialog.askdirectory(title='PBフォルダ' if is_input else '出力フォルダ')
        if value:
            var.set(value)
            if is_input and not output.get():output.set(str(Path(value).with_name(Path(value).name+'_extracted')))
    for label,var,which in [('PBフォルダ',source,'input'),('保存先',output,'output'),('追加XOR鍵（任意）',key,'key')]:
        row=ttk.Frame(root);row.pack(fill='x',pady=4);ttk.Label(row,text=label,width=20).pack(side='left')
        entry=ttk.Entry(row,textvariable=var);entry.pack(side='left',fill='x',expand=True,padx=(0,8));controls.append(entry)
        btn=ttk.Button(row,text='選択…',command=lambda v=var,w=which:pick(v,w=='input',w=='key'));btn.pack(side='right');controls.append(btn)
    group=ttk.LabelFrame(root,text='抽出するもの',padding=12);group.pack(fill='x',pady=14)
    variables={k:tk.BooleanVar(value=k in ('images','audio','video','resume')) for k in ('raw','images','audio','video','mp4','resume')}
    labels={'raw':'復号した原形式（全項目）','images':'画像 → PNG・透過復元','audio':'音声 → Ogg等・再生検証','video':'動画 → RM5等','mp4':'RM5 → MP4も変換（時間がかかります）','resume':'検証済みの出力をスキップして再開'}
    for i,k in enumerate(variables):
        cb=ttk.Checkbutton(group,text=labels[k],variable=variables[k]);cb.grid(row=i//2,column=i%2,sticky='w',padx=8,pady=5);controls.append(cb)
    ttk.Label(root,text='SNFS / SNMS対応。サブフォルダも検索します。未知の形式は失敗一覧に記録します。',wraplength=820).pack(anchor='w')
    ttk.Label(root,text='MP4は黒背景・音声なしで保存します。対応状況は同梱の「使い方.txt」を参照。',wraplength=820).pack(anchor='w',pady=(2,12))
    buttons=ttk.Frame(root);buttons.pack(fill='x')
    status=tk.StringVar(value='PBファイルのあるフォルダを選んでください。')
    progress=ttk.Progressbar(root,maximum=100);progress.pack(fill='x',pady=(15,6))
    ttk.Label(root,textvariable=status,wraplength=820).pack(anchor='w')
    log=ScrolledText(root,height=12,font=('Yu Gothic UI',9),state='disabled');log.pack(fill='both',expand=True,pady=(12,0))
    def write(message):
        log.configure(state='normal');log.insert('end',message+'\n');log.see('end');log.configure(state='disabled')
    def emit(kind,value):events.put((kind,value))
    def set_busy(value):
        busy[0]=value
        for c in controls:c.configure(state='disabled' if value else 'normal')
        stop.configure(state='normal' if value else 'disabled')
    def start(inspect=False):
        if busy[0]:return
        if not Path(source.get()).is_dir():messagebox.showerror('入力フォルダ','存在するPBフォルダを選択してください。');return
        opts={k:v.get() for k,v in variables.items()}
        if not inspect and (not output.get() or not any(opts[k] for k in ('raw','images','audio','video'))):messagebox.showerror('設定','保存先と抽出する項目を指定してください。');return
        if opts['mp4']:opts['video']=True;variables['video'].set(True)
        src,dst,custom=source.get(),output.get(),key.get();cancel.clear();set_busy(True);progress['value']=0;status.set('カタログを確認しています…')
        def worker():
            try:
                if inspect:
                    rows,errors=scan(src,cancel)
                    counts={name:sum(Path(x['name']).suffix.lower() in exts for x in rows) for name,exts in [('画像',IMAGES),('音声',AUDIO),('動画',VIDEO)]}
                    emit('log',f'全項目 {len(rows):,}件 / '+ ' / '.join(f'{k} {v:,}件' for k,v in counts.items()))
                    for e in errors:emit('log','カタログ失敗: '+str(e))
                    emit('done',{'status':'scan','catalog_errors':len(errors)})
                else:emit('done',run(src,dst,opts,cancel,emit,custom))
            except Cancelled:emit('done',{'status':'cancelled'})
            except Exception as ex:emit('error',str(ex));emit('log',traceback.format_exc())
        threading.Thread(target=worker,daemon=True).start()
    def stop_work():cancel.set();stop.configure(state='disabled');status.set('中断しています… 処理済みの成果物は保存されます。')
    for text,cmd in [('内容を確認',lambda:start(True)),('抽出を開始',start)]:
        b=ttk.Button(buttons,text=text,command=cmd);b.pack(side='left',padx=(0,10));controls.append(b)
    stop=ttk.Button(buttons,text='中断',command=stop_work,state='disabled');stop.pack(side='left')
    def open_output():
        if Path(output.get()).is_dir():os.startfile(output.get())
    ttk.Button(buttons,text='保存先を開く',command=open_output).pack(side='right')
    def poll():
        latest=None
        for _ in range(500):
            try:kind,value=events.get_nowait()
            except queue.Empty:break
            if kind=='progress':latest=value
            elif kind=='log':write(value)
            elif kind=='error':set_busy(False);status.set('エラー');messagebox.showerror('処理エラー',value)
            elif kind=='done':
                set_busy(False);write(json.dumps(value,ensure_ascii=False))
                if value['status']=='scan':status.set('内容の確認が終わりました。')
                elif value['status']=='cancelled':status.set('中断しました。「抽出を開始」で再開できます。')
                else:
                    progress['value']=100
                    message=f"完了：成功 {value['ok']:,}件 / 再開スキップ {value['skipped']:,}件 / 失敗 {value['failed']:,}件 / カタログエラー {value['catalog_errors']}件"
                    status.set(message);messagebox.showinfo('抽出結果',message+'\n\n保存先: '+value['output'])
                latest=None
        if latest:
            n,total,c,name=latest;progress['value']=100*n/max(1,total)
            status.set(f"{n:,} / {total:,}件  成功 {c['ok']:,}  スキップ {c['skipped']:,}  失敗 {c['failed']:,}  |  {name}")
        app.after(100,poll)
    def close():
        if busy[0]:
            if messagebox.askyesno('処理中','中断して終了しますか？'):
                stop_work()
                def wait_close():
                    if busy[0]:app.after(200,wait_close)
                    else:app.destroy()
                wait_close()
        else:app.destroy()
    app.protocol('WM_DELETE_WINDOW',close);poll()
    if '--gui-smoke' in sys.argv:
        def smoke():
            app.update()
            from PIL import ImageGrab
            import ctypes
            hwnd=ctypes.windll.user32.GetParent(app.winfo_id())
            ImageGrab.grab(window=hwnd).save(sys.argv[-1]+'.png')
            Path(sys.argv[-1]).write_text('GUI OK',encoding='utf8');app.destroy()
        app.after(1200,smoke)
    app.mainloop()

if __name__=='__main__':
    headless='--cli' in sys.argv or '--convert-video' in sys.argv
    try:main()
    except Exception:
        path=Path(os.environ.get('TEMP','.'))/'PBAssetTool-error.log';path.write_text(traceback.format_exc(),encoding='utf8')
        if headless:raise
        import tkinter.messagebox
        tkinter.messagebox.showerror('起動エラー',f'詳細: {path}\n'+traceback.format_exc()[-1000:])
