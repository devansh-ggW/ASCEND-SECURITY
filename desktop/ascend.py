import os, threading, time, tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from engine import scan_file, scan_folder, analyze_url, analyze_message, list_processes, list_connections, quarantine

BG='#050805'; PANEL='#0a100b'; PANEL2='#0d150e'; LINE='#17351c'; GREEN='#58ff78'; MUTED='#78907c'; WHITE='#e8f3e9'; WARN='#ffc857'; RED='#ff6565'
ROOT=Path(__file__).resolve().parent

class Ascend(tk.Tk):
    def __init__(self):
        super().__init__(); self.title('ASCEND Security'); self.geometry('1180x720'); self.minsize(980,620); self.configure(bg=BG)
        self.last_result=None; self.monitoring=True; self.after(1000,self.monitor_tick)
        self._set_icon(); self.build(); self.show_dashboard()
    def _set_icon(self):
        try:
            icon=tk.PhotoImage(file=str(ROOT/'assets'/'ascend_logo.gif')); self.iconphoto(True,icon); self._icon=icon
        except Exception: pass
    def build(self):
        top=tk.Frame(self,bg=BG,height=66); top.pack(fill='x'); top.pack_propagate(False)
        tk.Label(top,text='ASCEND',fg=GREEN,bg=BG,font=('Segoe UI',18,'bold')).pack(side='left',padx=(24,4),pady=16)
        tk.Label(top,text='SECURITY',fg=MUTED,bg=BG,font=('Segoe UI',9,'bold')).pack(side='left',pady=(20,15))
        tk.Label(top,text='●  LOCAL ENGINE ONLINE',fg=GREEN,bg=BG,font=('Consolas',9)).pack(side='right',padx=24)
        side=tk.Frame(self,bg=PANEL,width=210); side.pack(side='left',fill='y'); side.pack_propagate(False); self.side=side
        nav=[('◉','Dashboard',self.show_dashboard),('⌕','File Scanner',self.show_files),('↯','Quick Check',self.show_quick),('▣','Processes',self.show_processes),('≋','Network',self.show_network),('□','Quarantine',self.show_quarantine),('⚙','Settings',self.show_settings)]
        for sym,name,cmd in nav:
            b=tk.Button(side,text=f'{sym}  {name}',anchor='w',command=cmd,bg=PANEL,fg='#9bb29e',activebackground=PANEL2,activeforeground=GREEN,relief='flat',bd=0,font=('Segoe UI',10),padx=22,pady=12,cursor='hand2'); b.pack(fill='x')
        tk.Frame(side,bg=LINE,height=1).pack(fill='x',padx=18,pady=14)
        tk.Label(side,text='ASCEND CORE\nV1.0 DEVELOPMENT BUILD',fg='#506553',bg=PANEL,font=('Consolas',8),justify='left',padx=22).pack(anchor='w')
        self.content=tk.Frame(self,bg=BG); self.content.pack(side='left',fill='both',expand=True,padx=28,pady=24)
    def clear(self):
        for w in self.content.winfo_children(): w.destroy()
    def title(self,kicker,title,desc=''):
        tk.Label(self.content,text=kicker.upper(),fg=GREEN,bg=BG,font=('Consolas',9,'bold')).pack(anchor='w')
        tk.Label(self.content,text=title,fg=WHITE,bg=BG,font=('Segoe UI',27,'bold')).pack(anchor='w',pady=(5,2))
        if desc: tk.Label(self.content,text=desc,fg=MUTED,bg=BG,font=('Segoe UI',10),wraplength=850,justify='left').pack(anchor='w',pady=(0,18))
    def card(self,parent=None):
        f=tk.Frame(parent or self.content,bg=PANEL,highlightbackground=LINE,highlightthickness=1); f.pack(fill='x',pady=8); return f
    def button(self,parent,text,cmd,primary=False):
        return tk.Button(parent,text=text,command=cmd,bg=GREEN if primary else PANEL2,fg='#031006' if primary else GREEN,activebackground='#7dff96' if primary else '#122016',activeforeground='#031006' if primary else GREEN,relief='flat',font=('Segoe UI',9,'bold'),padx=16,pady=9,cursor='hand2')
    def show_dashboard(self):
        self.clear(); self.title('00 / STATUS','System protection overview','ASCEND is a defensive local-analysis platform. This build performs static inspection and read-only system visibility; it does not execute files.')
        hero=self.card(); hero.pack_configure(pady=(4,12)); left=tk.Frame(hero,bg=PANEL); left.pack(side='left',fill='both',expand=True,padx=25,pady=24)
        tk.Label(left,text='PROTECTED',fg=GREEN,bg=PANEL,font=('Segoe UI',31,'bold')).pack(anchor='w'); tk.Label(left,text='Local engine ready for analysis.',fg=MUTED,bg=PANEL,font=('Segoe UI',10)).pack(anchor='w')
        right=tk.Frame(hero,bg=PANEL); right.pack(side='right',padx=25,pady=22)
        for text,cmd in [('QUICK CHECK',self.show_quick),('SCAN FILE',self.pick_file),('SCAN FOLDER',self.pick_folder)]: self.button(right,text,cmd,primary=text=='QUICK CHECK').pack(side='left',padx=5)
        stats=tk.Frame(self.content,bg=BG); stats.pack(fill='x',pady=3)
        for label,value in [('REAL-TIME','READY'),('FILE ENGINE','READY'),('WEB SIGNALS','READY'),('QUARANTINE','AVAILABLE')]:
            f=tk.Frame(stats,bg=PANEL2,highlightbackground=LINE,highlightthickness=1); f.pack(side='left',fill='both',expand=True,padx=4)
            tk.Label(f,text=label,fg='#607563',bg=PANEL2,font=('Consolas',8)).pack(anchor='w',padx=14,pady=(12,2)); tk.Label(f,text=value,fg=GREEN,bg=PANEL2,font=('Consolas',12,'bold')).pack(anchor='w',padx=14,pady=(0,12))
        log=self.card(); tk.Label(log,text='ENGINE ACTIVITY',fg=GREEN,bg=PANEL,font=('Consolas',9,'bold')).pack(anchor='w',padx=18,pady=(14,6))
        self.activity=tk.Text(log,height=9,bg='#070b08',fg='#9ab29e',insertbackground=GREEN,relief='flat',font=('Consolas',9)); self.activity.pack(fill='x',padx=12,pady=(0,12)); self.activity.insert('1.0','[READY] ASCEND local detection engine initialized.\n[READY] Static file analysis available.\n[READY] Process and network views are read-only.\n'); self.activity.config(state='disabled')
    def log(self,text):
        if hasattr(self,'activity') and self.activity.winfo_exists(): self.activity.config(state='normal'); self.activity.insert('end',f'[{time.strftime("%H:%M:%S")}] {text}\n'); self.activity.see('end'); self.activity.config(state='disabled')
    def show_files(self):
        self.clear(); self.title('01 / FILE ENGINE','Advanced static file scanner','Analyze one file or an entire folder without executing it. The engine hashes files, inspects headers, extensions and selected suspicious execution strings.')
        actions=self.card(); self.button(actions,'SELECT FILE',self.pick_file,True).pack(side='left',padx=12,pady=14); self.button(actions,'SELECT FOLDER',self.pick_folder).pack(side='left',pady=14)
        box=self.card(); self.file_output=tk.Text(box,height=23,bg='#070b08',fg='#a9bcae',relief='flat',font=('Consolas',9),wrap='word'); self.file_output.pack(fill='both',expand=True,padx=12,pady=12); self.file_output.insert('1.0','Select a file to begin.\n\nSTATIC ONLY: ASCEND never launches the selected file.\n')
    def render_result(self,r):
        self.last_result=r
        txt=f'VERDICT   {r.verdict}\nRISK      {r.score}/100\nTARGET    {r.target}\nTYPE      {r.file_type}\nSIZE      {r.size:,} bytes\nTIME      {r.elapsed_ms} ms\n'
        if r.sha256: txt+=f'SHA-256   {r.sha256}\n'
        txt+='\nFINDINGS\n'+'-'*72+'\n'
        for x in r.findings: txt+=f'[{x.severity.upper():6}] {x.title}\n         {x.detail}\n'
        self.file_output.delete('1.0','end'); self.file_output.insert('1.0',txt)
        if r.score>=70: self.log(f'HIGH RISK: {Path(r.target).name}')
        elif r.score>=35: self.log(f'SUSPICIOUS: {Path(r.target).name}')
        else: self.log(f'LOW SIGNAL: {Path(r.target).name}')
        if r.score>=35: self.button(self.content,'QUARANTINE THIS FILE',self.do_quarantine).pack(anchor='w',padx=12,pady=4)
    def pick_file(self):
        p=filedialog.askopenfilename(title='ASCEND — Select a file')
        if not p: return
        self.show_files(); self.file_output.insert('end','\n[SCANNING] '+p+'\n'); self.update_idletasks();
        threading.Thread(target=lambda:self._file_scan(p),daemon=True).start()
    def _file_scan(self,p):
        r=scan_file(p); self.after(0,lambda:self.render_result(r))
    def pick_folder(self):
        p=filedialog.askdirectory(title='ASCEND — Select folder')
        if not p: return
        self.show_files(); self.file_output.insert('end','\n[SCANNING FOLDER] '+p+'\n'); threading.Thread(target=lambda:self._folder_scan(p),daemon=True).start()
    def _folder_scan(self,p):
        results=scan_folder(p); high=[r for r in results if r.score>=70]; sus=[r for r in results if 35<=r.score<70]
        def done():
            self.file_output.delete('1.0','end'); self.file_output.insert('1.0',f'FOLDER SCAN COMPLETE\n\nROOT       {p}\nFILES      {len(results)}\nHIGH RISK  {len(high)}\nSUSPICIOUS {len(sus)}\n\nTOP FINDINGS\n'+'-'*72+'\n')
            for r in sorted(results,key=lambda x:x.score,reverse=True)[:25]: self.file_output.insert('end',f'{r.score:3}  {r.verdict:10}  {r.target}\n')
        self.after(0,done)
    def do_quarantine(self):
        if not self.last_result or self.last_result.score<35: return
        try: dest=quarantine(self.last_result.target); self.log(f'QUARANTINED: {dest.name}'); messagebox.showinfo('ASCEND Quarantine',f'File moved to:\n{dest}')
        except Exception as e: messagebox.showerror('Quarantine failed',str(e))
    def show_quick(self):
        self.clear(); self.title('02 / QUICK CHECK','Inspect a suspicious URL or message','These checks are local heuristics. They do not contact or execute the destination.')
        tabs=tk.Frame(self.content,bg=BG); tabs.pack(fill='x'); self.quick_mode='url'
        for name,mode in [('URL','url'),('MESSAGE','message')]: self.button(tabs,name,lambda m=mode:self.set_quick(m)).pack(side='left',padx=(0,6))
        self.quick_box=tk.Frame(self.content,bg=BG); self.quick_box.pack(fill='both',expand=True); self.set_quick('url')
    def set_quick(self,mode):
        self.quick_mode=mode
        for w in self.quick_box.winfo_children(): w.destroy()
        f=self.card(self.quick_box); self.quick_input=tk.Text(f,height=10,bg='#070b08',fg=WHITE,insertbackground=GREEN,relief='flat',font=('Consolas',10)); self.quick_input.pack(fill='both',expand=True,padx=12,pady=12)
        self.quick_input.insert('1.0','https://example.com/login' if mode=='url' else 'Your account will be suspended. Send your verification code immediately.')
        self.button(f,'ANALYZE',self.analyze_quick,True).pack(anchor='e',padx=12,pady=(0,12))
        self.quick_result=tk.Label(self.quick_box,text='',anchor='nw',justify='left',bg=PANEL,fg='#a9bcae',font=('Consolas',9),wraplength=900,padx=16,pady=16); self.quick_result.pack(fill='x',pady=8)
    def analyze_quick(self):
        text=self.quick_input.get('1.0','end').strip(); r=analyze_url(text) if self.quick_mode=='url' else analyze_message(text)
        lines=[f'VERDICT: {r.verdict}    SCORE: {r.score}/100','']+[f'[{x.severity.upper()}] {x.title} — {x.detail}' for x in r.findings]
        self.quick_result.config(text='\n'.join(lines),fg=RED if r.score>=70 else WARN if r.score>=35 else GREEN); self.log(f'{self.quick_mode.upper()} check: {r.verdict}')
    def show_processes(self):
        self.clear(); self.title('03 / PROCESS VIEW','Running processes','Read-only visibility into Windows processes. ASCEND does not terminate or inject into processes.')
        b=self.card(); self.button(b,'REFRESH',self.show_processes,True).pack(anchor='w',padx=12,pady=12)
        tree=ttk.Treeview(self.content,columns=('name','pid','memory'),show='headings'); tree.heading('name',text='PROCESS'); tree.heading('pid',text='PID'); tree.heading('memory',text='MEMORY'); tree.column('name',width=450); tree.column('pid',width=100); tree.column('memory',width=160); tree.pack(fill='both',expand=True)
        style=ttk.Style(); style.theme_use('clam'); style.configure('Treeview',background='#070b08',foreground='#b7c8b9',fieldbackground='#070b08',rowheight=27); style.configure('Treeview.Heading',background='#0d150e',foreground=GREEN)
        for p in list_processes(): tree.insert('', 'end',values=(p['name'],p['pid'],p['memory']))
    def show_network(self):
        self.clear(); self.title('04 / NETWORK VIEW','Active network connections','Read-only output from the Windows network table. No packets are modified and no connections are created.')
        b=self.card(); self.button(b,'REFRESH',self.show_network,True).pack(anchor='w',padx=12,pady=12)
        t=tk.Text(self.content,bg='#070b08',fg='#9ab29e',relief='flat',font=('Consolas',8)); t.pack(fill='both',expand=True); lines=list_connections(); t.insert('1.0','\n'.join(lines) if lines else 'No network table data available.')
    def show_quarantine(self):
        self.clear(); self.title('05 / CONTAINMENT','Quarantine','Isolated files are moved into %LOCALAPPDATA%\\ASCEND\\Quarantine. This build intentionally has no automatic deletion.')
        from engine import QUARANTINE
        tk.Label(self.content,text=str(QUARANTINE),fg=MUTED,bg=BG,font=('Consolas',9)).pack(anchor='w',pady=(0,12))
        t=tk.Text(self.content,bg='#070b08',fg='#9ab29e',relief='flat',font=('Consolas',9)); t.pack(fill='both',expand=True)
        files=list(QUARANTINE.iterdir()) if QUARANTINE.exists() else []; t.insert('1.0','\n'.join(f'{p.name}    {p.stat().st_size:,} bytes' for p in files if p.is_file()) or 'Quarantine is empty.')
    def show_settings(self):
        self.clear(); self.title('06 / SETTINGS','ASCEND configuration','Development settings. Provider-backed reputation intelligence and continuous protection will be added as separate signed components later.')
        for title,val in [('Real-time monitoring','ON (development watcher)'),('Cloud reputation','NOT CONNECTED'),('Automatic deletion','OFF'),('File execution','NEVER')]:
            f=self.card(); tk.Label(f,text=title,fg=WHITE,bg=PANEL,font=('Segoe UI',10,'bold')).pack(side='left',padx=18,pady=15); tk.Label(f,text=val,fg=GREEN if val.startswith('ON') or val=='NEVER' else WARN,bg=PANEL,font=('Consolas',9)).pack(side='right',padx=18)
        tk.Label(self.content,text='ASCEND is currently a defensive development build. A production antivirus requires signed native components, a hardened update channel and a carefully isolated analysis/reputation backend.',fg=MUTED,bg=BG,font=('Segoe UI',9),wraplength=850,justify='left').pack(anchor='w',pady=15)
    def monitor_tick(self):
        # Lightweight heartbeat only; no filesystem mutation.
        if self.monitoring: pass
        self.after(2500,self.monitor_tick)

if __name__=='__main__':
    Ascend().mainloop()
