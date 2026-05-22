global mitmproxy_master
global keyauthapp
import os
import subprocess
import time
import sys
from threading import Thread
import asyncio
import json
import winreg
import platform
import random
import atexit
import signal
import ctypes
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import messagebox
THEME = {'bg': '#050505', 'panel': '#0A0A0F', 'border': '#1A1A24', 'accent': '#E60000', 'accent_hover': '#FF1A1A', 'text_main': '#FFFFFF', 'text_muted': '#666680', 'success': '#00FF41', 'font_main': 'Consolas', 'font_mono': 'Consolas'}
class NullWriter:
    def write(self, text):
        return None
    def flush(self):
        return None
    def isatty(self):
        return False
if sys.stdout is None:
    sys.stdout = NullWriter()
if sys.stderr is None:
    sys.stderr = NullWriter()
DEPENDENCIES_OK = False
try:
    import customtkinter as ctk
    from PIL import Image
    import mitmproxy
    from mitmproxy.tools.dump import DumpMaster
    from mitmproxy.options import Options
    import requests
    from keyauth import api
    DEPENDENCIES_OK = True
except Exception as e:
    pass
APP_NAME = 'NULLMASK'
APP_VERSION = '6.0.0-FREE'
MITMPROXY_LISTEN_HOST = '127.0.0.1'
MITMPROXY_LISTEN_PORT = 8080
keyauthapp = None
if sys.platform == 'win32':
    APP_DIR = os.path.join(os.getenv('APPDATA'), 'NullMask')
else:
    APP_DIR = os.path.join(os.path.expanduser('~'), '.config', 'NullMask')
os.makedirs(APP_DIR, exist_ok=True)
CONFIG_FILE_PATH = os.path.join(APP_DIR, 'config.json')
mitmproxy_master = None
mitmproxy_fully_running_event = asyncio.Event()
REQUIRED_PACKAGES = ['customtkinter', 'mitmproxy', 'requests', 'pillow', 'qrcode', 'discord_interactions', 'pywin32']
def disable_system_proxy():
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 0)
        winreg.CloseKey(key)
    except:
        return False
    else:
        return True
def set_system_proxy(host, port):
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings', 0, winreg.KEY_WRITE)
        winreg.SetValueEx(key, 'ProxyEnable', 0, winreg.REG_DWORD, 1)
        winreg.SetValueEx(key, 'ProxyServer', 0, winreg.REG_SZ, f'{host}:{port}')
        winreg.SetValueEx(key, 'ProxyOverride', 0, winreg.REG_SZ, '<local>;*.epicgames.com;*.psyonix.com;*.live.psynet.gg')
        winreg.CloseKey(key)
    except:
        return False
    else:
        return True
atexit.register(disable_system_proxy)
signal.signal(signal.SIGINT, lambda sig, frame: (disable_system_proxy(), sys.exit(0)))
def is_mitmproxy_cert_installed():
    if platform.system()!= 'Windows':
        return True
    else:
        ps_command = '$cert = Get-ChildItem -Path Cert:\\CurrentUser\\Root | Where-Object { $_.Subject -like \'*mitmproxy*\' }; if ($cert) { Write-Output \'Found\' }'
        result = subprocess.run(['powershell', '-Command', ps_command], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
        return 'Found' in result.stdout
def install_mitmproxy_cert():
    if platform.system()!= 'Windows':
        return False
    else:
        try:
            ps_script = '\n        $certPath = \"$env:USERPROFILE\\.mitmproxy\\mitmproxy-ca-cert.p12\"\n        if (-not (Test-Path $certPath)) { exit 1 }\n        $cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath, \"\", [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)\n        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store([System.Security.Cryptography.X509Certificates.StoreName]::Root, [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser)\n        $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)\n        $store.Add($cert)\n        $store.Close()\n        Write-Output \"Success\"\n        '
            result = subprocess.run(['powershell', '-Command', ps_script], capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW)
            return 'Success' in result.stdout
        except:
            return False
def remove_mitmproxy_cert():
    if platform.system()!= 'Windows':
        return False
    else:
        try:
            ps_script = 'Get-ChildItem -Path Cert:\\CurrentUser\\Root | Where-Object { $_.Subject -like \'*mitmproxy*\' } | Remove-Item'
            subprocess.run(['powershell', '-Command', ps_script], creationflags=subprocess.CREATE_NO_WINDOW)
        except:
            return False
        else:
            return True
class NameSpoofAddon:
    def __init__(self, new_name, log_callback, packet_callback):
        self.new_name = new_name
        self.log_callback = log_callback
        self.packet_callback = packet_callback
    def response(self, flow):
        # irreducible cflow, using cdg fallback
        # ***<module>.NameSpoofAddon.response: Failure: Compilation Error
        target_domains = ['epicgames.dev', 'epicgames.com', 'psyonix.com', 'live.psynet.gg']
        if any((domain in flow.request.pretty_host for domain in target_domains)):
            if 'application/json' in flow.response.headers.get('Content-Type', ''):
                pass
        body_data = flow.response.json()
        spoofed = False
        if isinstance(body_data, list) and len(body_data) == 1 and isinstance(body_data[0], dict) and ('displayName' in body_data[0]):
                        old_name = body_data[0]['displayName']
                        body_data[0]['displayName'] = self.new_name
                        spoofed = True
                        self.log_callback(f'[+] MEM_OVERWRITE: \'{old_name}\' -> \'{self.new_name}\'')
                        self.packet_callback()
        if spoofed:
            flow.response.content = json.dumps(body_data, ensure_ascii=False).encode('utf-8')
            return
def run_mitmproxy_thread_target(new_name, log_cb, packet_cb):
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        async def run_proxy_async():
            global mitmproxy_master
            options = Options(listen_host=MITMPROXY_LISTEN_HOST, listen_port=MITMPROXY_LISTEN_PORT, mode=['regular'])
            mitmproxy_master = DumpMaster(options, with_termlog=False)
            mitmproxy_master.addons.add(NameSpoofAddon(new_name, log_cb, packet_cb))
            mitmproxy_master.options.block_global = False
            mitmproxy_fully_running_event.set()
            await mitmproxy_master.run()
        loop.run_until_complete(run_proxy_async())
    except Exception as e:
        log_cb(f'[!] ENGINE_FATAL: {str(e)}')
        disable_system_proxy()
class NullMaskGUI:
    def __init__(self, master):
        self.master = master
        self.pages = {}
        self.is_proxy_running = False
        self.nav_buttons = {}
        self.saved_key = ''
        self.saved_name = 'Zen'
        self.start_time = time.time()
        self.packets_injected = 0
        self.expiry_timestamp = 0
        self.graph_data = [20] * 50
        self.scan_line_y = 0
        try:
            self.master.iconbitmap('logo.ico')
        except:
            pass
        if not DEPENDENCIES_OK:
            self.show_install_screen()
            return None
        else:
            ctk.set_appearance_mode('Dark')
            self.master.title(f'{APP_NAME} // DEVELOPED BY MIHAI')
            width, height = (1150, 750)
            sw = self.master.winfo_screenwidth()
            sh = self.master.winfo_screenheight()
            self.master.geometry(f'{width}x{height}+{(sw - width) // 2}+{(sh - height) // 2}')
            self.master.resizable(False, False)
            self.load_logo_image()
            self.setup_window()
            self.load_config()
            self.show_login_screen()
            self.update_live_stats()
    def decorative_frame(self, parent, **kwargs):
        opts = {'corner_radius': 0, 'border_width': 1, 'border_color': THEME['border'], 'fg_color': THEME['panel']}
        opts.update(kwargs)
        f = ctk.CTkFrame(parent, **opts)
        return f
    def show_install_screen(self):
        self.master.title('BOOT_SEQ // INSTALL')
        width, height = (650, 450)
        sw = self.master.winfo_screenwidth()
        sh = self.master.winfo_screenheight()
        self.master.geometry(f'{width}x{height}+{(sw - width) // 2}+{(sh - height) // 2}')
        self.master.configure(bg=THEME['bg'])
        self.master.resizable(False, False)
        container = tk.Frame(self.master, bg=THEME['bg'], bd=1, relief='solid', highlightbackground=THEME['accent'], highlightthickness=1)
        container.pack(expand=True, fill='both', padx=20, pady=20)
        tk.Label(container, text='[ NULLMASK CORE // FREE SPOOFER ]', font=(THEME['font_mono'], 20, 'bold'), bg=THEME['bg'], fg=THEME['accent']).pack(anchor='w', padx=20, pady=(20, 5))
        tk.Label(container, text='SYS.WARN: MISSING CORE DEPENDENCIES', font=(THEME['font_mono'], 10), bg=THEME['bg'], fg=THEME['text_muted']).pack(anchor='w', padx=20, pady=(0, 20))
        self.term = tk.Text(container, bg=THEME['panel'], fg=THEME['text_main'], font=(THEME['font_mono'], 10), bd=1, relief='solid', highlightbackground=THEME['border'], highlightthickness=1, padx=15, pady=15, height=12)
        self.term.pack(fill='x', padx=20, pady=(0, 20))
        self.term.insert('end', '> root@mihai-sec:~# ./install_deps.sh\n> Awaiting user confirmation...\n')
        self.term.configure(state='disabled')
        def append_term(text):
            self.term.configure(state='normal')
            self.term.insert('end', text + '\n')
            self.term.see('end')
            self.term.configure(state='disabled')
            self.master.update()
        def install_task():
            self.btn_install.config(state='disabled', text='[ EXECUTING BUILD SEQUENCE ]', bg=THEME['border'])
            for pkg in REQUIRED_PACKAGES:
                append_term(f'> apt-get install {pkg} ...')
                try:
                    kwargs = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
                    subprocess.call([sys.executable, '-m', 'pip', 'install', pkg], **kwargs)
                    append_term(f'  [OK] {pkg} injected.')
                except Exception as e:
                    append_term(f'  [ERR] {str(e)}')
            append_term('\n> SYS.REBOOT INITIATED...')
            self.master.update()
            time.sleep(1.5)
            os.execv(sys.executable, ['python'] + sys.argv)
        def start_install():
            Thread(target=install_task, daemon=True).start()
        self.btn_install = tk.Button(container, text='[ DEPLOY PACKAGES ]', font=(THEME['font_mono'], 12, 'bold'), bg=THEME['bg'], fg=THEME['accent'], bd=1, relief='solid', highlightbackground=THEME['accent'], highlightthickness=1, activebackground=THEME['accent'], activeforeground=THEME['bg'], pady=10, cursor='hand2', command=start_install)
        self.btn_install.pack(fill='x', padx=20)
    def load_logo_image(self):
        self.logo_img_small = None
        if os.path.exists('logo.ico'):
            try:
                img = Image.open('logo.ico')
                self.logo_img_small = ctk.CTkImage(light_image=img, dark_image=img, size=(20, 20))
            except Exception:
                return None
    def setup_window(self):
        if platform.system() == 'Windows':
            self.master.overrideredirect(True)
            self.master.bind('<Map>', self.on_window_map)
            self.master.after(100, self.set_appwindow)
        self.app_frame = ctk.CTkFrame(self.master, fg_color=THEME['bg'], corner_radius=0, border_width=1, border_color=THEME['accent'])
        self.app_frame.pack(fill='both', expand=True, padx=2, pady=2)
        self.create_custom_titlebar(self.app_frame, bg_color=THEME['panel'])
        self.content_container = ctk.CTkFrame(self.app_frame, fg_color='transparent', corner_radius=0)
        self.content_container.pack(fill='both', expand=True)
    def set_appwindow(self):
        if platform.system() == 'Windows':
            try:
                hwnd = ctypes.windll.user32.GetParent(self.master.winfo_id())
                GWL_EXSTYLE = (-20)
                WS_EX_APPWINDOW = 262144
                WS_EX_TOOLWINDOW = 128
                style = ctypes.windll.user32.GetWindowLongW(hwnd, GWL_EXSTYLE)
                style = style & ~WS_EX_TOOLWINDOW
                style = style | WS_EX_APPWINDOW
                ctypes.windll.user32.SetWindowLongW(hwnd, GWL_EXSTYLE, style)
                self.master.withdraw()
                self.master.after(10, self.master.deiconify)
            except:
                return None
    def start_move(self, event):
        self.x = event.x
        self.y = event.y
    def do_move(self, event):
        self.master.geometry(f'+{self.master.winfo_x() + event.x - self.x}+{self.master.winfo_y() + event.y - self.y}')
    def on_window_map(self, event):
        if event.widget == self.master and self.master.state() == 'normal' and (not self.master.overrideredirect()):
                    self.master.overrideredirect(True)
                    self.set_appwindow()
    def create_custom_titlebar(self, parent, bg_color='transparent'):
        title_bar = ctk.CTkFrame(parent, height=30, corner_radius=0, fg_color=bg_color, border_width=1, border_color=THEME['border'])
        title_bar.pack(fill='x', side='top')
        title_bar.bind('<ButtonPress-1>', self.start_move)
        title_bar.bind('<B1-Motion>', self.do_move)
        lbl = ctk.CTkLabel(title_bar, text=f'  NULLMASK.EXE // PID: {os.getpid()} // FREE_TIER', font=(THEME['font_mono'], 10, 'bold'), text_color=THEME['text_muted'])
        lbl.pack(side='left', padx=10)
        lbl.bind('<ButtonPress-1>', self.start_move)
        lbl.bind('<B1-Motion>', self.do_move)
        ctk.CTkButton(title_bar, text='[ X ]', width=30, height=30, corner_radius=0, fg_color='transparent', hover_color=THEME['accent'], text_color=THEME['text_muted'], font=(THEME['font_mono'], 12), command=self.on_closing).pack(side='right')
        return title_bar
    def show_login_screen(self):
        self.login_frame = ctk.CTkFrame(self.content_container, fg_color='transparent')
        self.login_frame.pack(fill='both', expand=True)
        self.bg_canvas = tk.Canvas(self.login_frame, bg=THEME['bg'], bd=0, highlightthickness=0)
        self.bg_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.draw_bg_grid(self.bg_canvas, 1150, 750)
        center_card = self.decorative_frame(self.login_frame, width=480, height=350)
        center_card.place(relx=0.5, rely=0.5, anchor='center')
        center_card.pack_propagate(False)
        hdr = ctk.CTkFrame(center_card, height=2, fg_color=THEME['accent'], corner_radius=0)
        hdr.pack(fill='x', side='top')
        ctk.CTkLabel(center_card, text='[ NULLMASK CORE ]', font=(THEME['font_mono'], 20, 'bold'), text_color=THEME['text_main']).pack(pady=(35, 5))
        ctk.CTkLabel(center_card, text='DEVELOPED BY MIHAI', font=(THEME['font_mono'], 12, 'bold'), text_color=THEME['accent']).pack(pady=(0, 20))
        ctk.CTkLabel(center_card, text='> INPUT LICENSE HASH:', font=(THEME['font_mono'], 11), text_color=THEME['text_muted']).pack(anchor='w', padx=50)
        self.key_var = ctk.StringVar(value=self.saved_key)
        self.key_entry = ctk.CTkEntry(center_card, textvariable=self.key_var, placeholder_text='XXXX-XXXX-XXXX-XXXX', height=45, font=(THEME['font_mono'], 14), corner_radius=0, fg_color=THEME['bg'], border_width=1, border_color=THEME['border'], text_color=THEME['text_main'], justify='center')
        self.key_entry.pack(fill='x', padx=50, pady=(5, 25))
        self.auth_btn = ctk.CTkButton(center_card, text='[ DECRYPT & INITIALIZE ]', height=45, font=(THEME['font_mono'], 14, 'bold'), corner_radius=0, border_width=1, border_color=THEME['accent'], fg_color='transparent', hover_color=THEME['accent'], text_color=THEME['accent'], command=self.process_login)
        self.auth_btn.pack(fill='x', padx=50)
        self.login_status = ctk.CTkLabel(center_card, text='Awaiting input...', font=(THEME['font_mono'], 11), text_color=THEME['text_muted'])
        self.login_status.pack(pady=(20, 0))
    def draw_bg_grid(self, canvas, w, h):
        for i in range(0, w, 30):
            canvas.create_line(i, 0, i, h, fill='#0A0A0A')
        for i in range(0, h, 30):
            canvas.create_line(0, i, w, i, fill='#0A0A0A')
    def process_login(self):
        global keyauthapp
        key = self.key_var.get().strip()
        if not key:
            self.login_status.configure(text='[!] ERROR: EMPTY HASH', text_color=THEME['accent'])
            return None
        else:
            self.auth_btn.configure(state='disabled', text='[ PROCESSING... ]')
            self.login_status.configure(text='> Handshaking with secure auth servers...', text_color=THEME['text_main'])
            self.master.update()
            try:
                if keyauthapp is None:
                    keyauthapp = api(name='NullMask Name Spoofer Free', ownerid='jTfNpN6GyS', version='1.0', hash_to_check='')
                keyauthapp.license(key)
                try:
                    self.expiry_timestamp = int(keyauthapp.user_data.expires)
                except:
                    self.expiry_timestamp = int(time.time()) + 2592000
                self.login_status.configure(text='[+] ACCESS GRANTED. BYPASSING MAIN_FRAME.', text_color=THEME['success'])
                self.master.update()
                time.sleep(0.5)
                self.login_success()
            except Exception as e:
                self.login_status.configure(text=f'[!] {str(e).upper()}', text_color=THEME['accent'])
                self.auth_btn.configure(state='normal', text='[ DECRYPT & INITIALIZE ]', text_color=THEME['accent'])
    def login_success(self):
        self.saved_key = self.key_var.get().strip()
        self.save_config()
        self.login_frame.destroy()
        self.create_layout()
        self.show_page('main')
    def create_layout(self):
        self.top_hud = ctk.CTkFrame(self.content_container, height=50, corner_radius=0, fg_color=THEME['panel'], border_width=1, border_color=THEME['border'])
        self.top_hud.pack(side='top', fill='x', padx=10, pady=(10, 5))
        self.top_hud.pack_propagate(False)
        if self.logo_img_small:
            ctk.CTkLabel(self.top_hud, text='', image=self.logo_img_small).pack(side='left', padx=(15, 5))
        ctk.CTkLabel(self.top_hud, text='NULLMASK', font=(THEME['font_main'], 16, 'bold'), text_color=THEME['text_main']).pack(side='left')
        ctk.CTkLabel(self.top_hud, text=' // DEV: MIHAI', font=(THEME['font_mono'], 12, 'bold'), text_color=THEME['accent']).pack(side='left')
        self.lbl_mem_reg = ctk.CTkLabel(self.top_hud, text='MEM: 0x00000000', font=(THEME['font_mono'], 10), text_color=THEME['text_muted'])
        self.lbl_mem_reg.pack(side='right', padx=15)
        self.lbl_uptime = ctk.CTkLabel(self.top_hud, text='UPTIME: 00:00:00', font=(THEME['font_mono'], 10), text_color=THEME['text_muted'])
        self.lbl_uptime.pack(side='right', padx=15)
        body = ctk.CTkFrame(self.content_container, fg_color='transparent')
        body.pack(fill='both', expand=True, padx=10, pady=5)
        self.sidebar = self.decorative_frame(body, width=280)
        self.sidebar.pack(side='left', fill='y', pady=(0, 10))
        self.sidebar.pack_propagate(False)
        ctk.CTkLabel(self.sidebar, text='COMMAND MATRIX', font=(THEME['font_mono'], 12, 'bold'), text_color=THEME['text_muted']).pack(anchor='w', padx=20, pady=(20, 10))
        ctk.CTkFrame(self.sidebar, height=1, fg_color=THEME['border'], corner_radius=0).pack(fill='x', padx=15, pady=(0, 15))
        self.nav_container = ctk.CTkFrame(self.sidebar, fg_color='transparent')
        self.nav_container.pack(fill='x', padx=15)
        self.btn_main = self.create_nav_btn('main', '[01] INJECTION_BAY', lambda: self.show_page('main'))
        self.btn_how = self.create_nav_btn('how', '[02] DOCUMENTATION', lambda: self.show_page('how'))
        self.btn_sys = self.create_nav_btn('sys', '[03] SYS_CONFIG', lambda: self.show_page('sys'))
        bot_frame = ctk.CTkFrame(self.sidebar, fg_color='transparent')
        bot_frame.pack(side='bottom', fill='x', padx=15, pady=20)
        self.lbl_expiry = ctk.CTkLabel(bot_frame, text='Checking expiry...', font=(THEME['font_mono'], 11, 'bold'), text_color=THEME['success'])
        self.lbl_expiry.pack(anchor='w', pady=(0, 15))
        ctk.CTkButton(bot_frame, text='[ DISCONNECT ]', font=(THEME['font_mono'], 12, 'bold'), height=40, corner_radius=0, border_width=1, border_color=THEME['border'], fg_color='transparent', hover_color=THEME['accent'], text_color=THEME['text_muted'], command=self.on_closing).pack(fill='x')
        self.page_container = ctk.CTkFrame(body, fg_color='transparent', corner_radius=0)
        self.page_container.pack(side='right', fill='both', expand=True, padx=(10, 0), pady=(0, 10))
    def create_nav_btn(self, name, text, command):
        btn = ctk.CTkButton(self.nav_container, text=text, font=(THEME['font_mono'], 12), height=40, corner_radius=0, fg_color='transparent', border_width=1, border_color=THEME['panel'], text_color=THEME['text_muted'], hover_color=THEME['border'], anchor='w', command=command)
        btn.pack(fill='x', pady=4)
        self.nav_buttons[name] = btn
        return btn
    def update_nav_active_state(self, active_name):
        for name, btn in self.nav_buttons.items():
            if name == active_name:
                btn.configure(border_color=THEME['accent'], text_color=THEME['text_main'], fg_color=THEME['bg'])
            else:
                btn.configure(border_color=THEME['panel'], text_color=THEME['text_muted'], fg_color='transparent')
    def log_to_console(self, msg):
        def update_ui():
            if hasattr(self, 'console_textbox'):
                self.console_textbox.configure(state='normal')
                ts = datetime.now().strftime('%H:%M:%S')
                self.console_textbox.insert('end', f'[{ts}] {msg}\n')
                self.console_textbox.see('end')
                self.console_textbox.configure(state='disabled')
        self.master.after(0, update_ui)
    def increment_packets(self):
        self.packets_injected += 1
    def draw_graph(self):
        if not hasattr(self, 'graph_canvas'):
            return None
        else:
            w = self.graph_canvas.winfo_width()
            h = self.graph_canvas.winfo_height()
            if w < 10:
                return None
            else:
                self.graph_canvas.delete('all')
                for i in range(0, w, 30):
                    self.graph_canvas.create_line(i, 0, i, h, fill=THEME['border'], dash=(2, 4))
                for i in range(0, h, 30):
                    self.graph_canvas.create_line(0, i, w, i, fill=THEME['border'], dash=(2, 4))
                if self.is_proxy_running:
                    self.graph_data.pop(0)
                    self.graph_data.append(random.randint(15, h - 15))
                    self.scan_line_y += 4
                    if self.scan_line_y > w:
                        self.scan_line_y = 0
                    self.graph_canvas.create_line(self.scan_line_y, 0, self.scan_line_y, h, fill='#FF003C', width=1)
                else:
                    self.graph_data = [h - 2] * 50
                step = w / (len(self.graph_data) - 1)
                points = []
                for i, val in enumerate(self.graph_data):
                    points.append(i * step)
                    points.append(h - val)
                line_color = THEME['accent'] if self.is_proxy_running else THEME['text_muted']
                self.graph_canvas.create_line(points, fill=line_color, width=2, smooth=False)
                if self.is_proxy_running:
                    for i in range(0, len(points), 4):
                        x, y = (points[i], points[i + 1])
                        self.graph_canvas.create_rectangle(x - 2, y - 2, x + 2, y + 2, fill=THEME['bg'], outline=THEME['accent'])
    def update_live_stats(self):
        if hasattr(self, 'lbl_uptime'):
            up = int(time.time() - self.start_time)
            m, s = divmod(up, 60)
            h, m = divmod(m, 60)
            self.lbl_uptime.configure(text=f'UPTIME: {h:02d}:{m:02d}:{s:02d}')
        if hasattr(self, 'lbl_mem_reg'):
            self.lbl_mem_reg.configure(text=f'MEM: 0x{random.randint(10000000, 99999999):X}')
        if hasattr(self, 'lbl_expiry') and hasattr(self, 'expiry_timestamp'):
                now = int(time.time())
                time_left = self.expiry_timestamp - now
                if time_left > 0:
                    days = time_left // 86400
                    hours = time_left % 86400 // 3600
                    self.lbl_expiry.configure(text=f'LICENSE: {days}D {hours}H REMAINING', text_color=THEME['success'])
                else:
                    self.lbl_expiry.configure(text='LICENSE: EXPIRED', text_color=THEME['accent'])
        if hasattr(self, 'is_proxy_running') and hasattr(self, 'telemetry_ping'):
                if self.is_proxy_running:
                    self.telemetry_ping.configure(text=f'{random.randint(12, 28)} ms', text_color=THEME['success'])
                    self.telemetry_packets.configure(text=f'{self.packets_injected}', text_color=THEME['accent'])
                    self.status_lbl.configure(text='[ ENGINE: INJECTING ]', text_color=THEME['accent'])
                else:
                    self.telemetry_ping.configure(text='-- ms', text_color=THEME['text_main'])
                    self.status_lbl.configure(text='[ ENGINE: IDLE ]', text_color=THEME['text_muted'])
                self.draw_graph()
        self.master.after(1000, self.update_live_stats)
    def set_random_name(self):
        adj = random.choice(['Void', 'Null', 'Hex', 'Root', 'Cyber', 'Dark', 'Ghost'])
        noun = random.choice(['Byte', 'Flow', 'Zero', 'Proxy', 'Core'])
        self.name_var.set(f'{adj}_{noun}_{random.randint(100, 999)}')
    def create_main_page(self):
        page = ctk.CTkFrame(self.page_container, fg_color='transparent')
        self.pages['main'] = page
        grid = ctk.CTkFrame(page, fg_color='transparent')
        grid.pack(fill='both', expand=True)
        left_col = ctk.CTkFrame(grid, fg_color='transparent')
        left_col.pack(side='left', fill='both', expand=True, padx=(0, 5))
        right_col = ctk.CTkFrame(grid, fg_color='transparent')
        right_col.pack(side='right', fill='both', expand=True, padx=(5, 0))
        alias_card = self.decorative_frame(left_col)
        alias_card.pack(fill='x', pady=(0, 10))
        ctk.CTkLabel(alias_card, text='// TARGET ALIAS', font=(THEME['font_mono'], 11, 'bold'), text_color=THEME['text_main']).pack(anchor='w', padx=20, pady=(15, 5))
        self.name_var = ctk.StringVar(value=self.saved_name)
        inp_f = ctk.CTkFrame(alias_card, fg_color='transparent')
        inp_f.pack(fill='x', padx=20, pady=(0, 20))
        self.entry = ctk.CTkEntry(inp_f, textvariable=self.name_var, height=45, font=(THEME['font_mono'], 16), corner_radius=0, fg_color=THEME['bg'], border_width=1, border_color=THEME['border'], text_color=THEME['text_main'])
        self.entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        ctk.CTkButton(inp_f, text='[ RAND ]', width=80, height=45, font=(THEME['font_mono'], 11, 'bold'), corner_radius=0, border_width=1, border_color=THEME['border'], fg_color=THEME['bg'], hover_color=THEME['border'], text_color=THEME['text_main'], command=self.set_random_name).pack(side='left')
        btn_frame = self.decorative_frame(left_col, border_color=THEME['accent'])
        btn_frame.pack(fill='x', pady=(0, 10))
        self.status_lbl = ctk.CTkLabel(btn_frame, text='[ ENGINE: IDLE ]', font=(THEME['font_mono'], 10), text_color=THEME['text_muted'])
        self.status_lbl.pack(pady=(10, 0))
        self.toggle_btn = ctk.CTkButton(btn_frame, text='INITIATE OVERWRITE', command=self.toggle_proxy, height=55, font=(THEME['font_main'], 18, 'bold'), corner_radius=0, fg_color=THEME['accent'], text_color='#FFFFFF', hover_color=THEME['accent_hover'])
        self.toggle_btn.pack(fill='x', padx=15, pady=(5, 15))
        graph_card = self.decorative_frame(left_col)
        graph_card.pack(fill='both', expand=True)
        ctk.CTkLabel(graph_card, text='// NETWORK RADAR', font=(THEME['font_mono'], 11, 'bold'), text_color=THEME['text_main']).pack(anchor='w', padx=20, pady=(15, 0))
        gf = tk.Frame(graph_card, bg=THEME['panel'], bd=1, relief='solid', highlightbackground=THEME['border'], highlightthickness=1)
        gf.pack(fill='both', expand=True, padx=20, pady=(10, 20))
        self.graph_canvas = tk.Canvas(gf, bg=THEME['bg'], bd=0, highlightthickness=0)
        self.graph_canvas.pack(fill='both', expand=True)
        stats_row = ctk.CTkFrame(right_col, fg_color='transparent')
        stats_row.pack(fill='x', pady=(0, 10))
        ping_card = self.decorative_frame(stats_row)
        ping_card.pack(side='left', fill='both', expand=True, padx=(0, 5))
        ctk.CTkLabel(ping_card, text='PING (MS)', font=(THEME['font_mono'], 10), text_color=THEME['text_muted']).pack(pady=(15, 0))
        self.telemetry_ping = ctk.CTkLabel(ping_card, text='-- ms', font=(THEME['font_mono'], 24, 'bold'), text_color=THEME['text_main'])
        self.telemetry_ping.pack(pady=(0, 15))
        pkt_card = self.decorative_frame(stats_row)
        pkt_card.pack(side='right', fill='both', expand=True, padx=(5, 0))
        ctk.CTkLabel(pkt_card, text='HOOKS', font=(THEME['font_mono'], 10), text_color=THEME['text_muted']).pack(pady=(15, 0))
        self.telemetry_packets = ctk.CTkLabel(pkt_card, text='0', font=(THEME['font_mono'], 24, 'bold'), text_color=THEME['text_main'])
        self.telemetry_packets.pack(pady=(0, 15))
        term_card = self.decorative_frame(right_col)
        term_card.pack(fill='both', expand=True)
        t_head = ctk.CTkFrame(term_card, fg_color='transparent')
        t_head.pack(fill='x', padx=20, pady=(15, 0))
        ctk.CTkLabel(t_head, text='// SYS.TERM_OUT', font=(THEME['font_mono'], 11, 'bold'), text_color=THEME['text_main']).pack(side='left')
        ctk.CTkLabel(t_head, text='[ ROOT_ACCESS ]', font=(THEME['font_mono'], 10), text_color=THEME['accent']).pack(side='right')
        self.console_textbox = ctk.CTkTextbox(term_card, font=(THEME['font_mono'], 11), fg_color=THEME['bg'], corner_radius=0, text_color=THEME['text_muted'], border_width=1, border_color=THEME['border'])
        self.console_textbox.pack(fill='both', expand=True, padx=20, pady=(10, 20))
        self.console_textbox.insert('end', '>> NULLMASK ENGINE INITIALIZED...\n>> WAITING FOR DIRECTIVES...\n')
        self.console_textbox.configure(state='disabled')
        return page
    def create_how_page(self):
        page = ctk.CTkFrame(self.page_container, fg_color='transparent')
        self.pages['how'] = page
        card = self.decorative_frame(page)
        card.pack(fill='both', expand=True)
        ctk.CTkLabel(card, text='// DOCUMENTATION & PROTOCOLS', font=(THEME['font_mono'], 14, 'bold'), text_color=THEME['accent']).pack(anchor='w', padx=25, pady=(25, 10))
        scroll = ctk.CTkScrollableFrame(card, fg_color='transparent')
        scroll.pack(fill='both', expand=True, padx=10, pady=(0, 20))
        steps = [('0x01. TARGETING', 'Input desired alias string in [ TARGET ALIAS ]. Use [ RAND ] to generate a randomized cryptographic hash-like name.'), ('0x02. DEPLOYMENT', 'Execute [ INITIATE OVERWRITE ]. The internal MitmProxy core will hijack local routing tables and begin packet inspection.'), ('0x03. EXFILTRATION', 'Click [ HALT INJECTION ] to disable the routing hijack and restore standard Windows net configurations securely.')]
        for title, body in steps:
            s_card = self.decorative_frame(scroll, border_color=THEME['bg'])
            s_card.pack(fill='x', pady=(0, 15))
            ctk.CTkLabel(s_card, text=title, font=(THEME['font_mono'], 12, 'bold'), text_color=THEME['text_main']).pack(anchor='w', padx=20, pady=(15, 0))
            ctk.CTkLabel(s_card, text=f'> {body}', font=(THEME['font_main'], 12), text_color=THEME['text_muted'], justify='left', wraplength=650).pack(anchor='w', padx=20, pady=(5, 15))
        return page
    def create_sys_page(self):
        page = ctk.CTkFrame(self.page_container, fg_color='transparent')
        self.pages['sys'] = page
        scroll = ctk.CTkScrollableFrame(page, fg_color='transparent')
        scroll.pack(fill='both', expand=True)
        ca_card = self.decorative_frame(scroll)
        ca_card.pack(fill='x', pady=(0, 15))
        ctk.CTkLabel(ca_card, text='// SECURE CERTIFICATE (CA)', font=(THEME['font_mono'], 14, 'bold'), text_color=THEME['text_main']).pack(anchor='w', padx=25, pady=(20, 5))
        ctk.CTkLabel(ca_card, text='> Inject MitmProxy Root CA into Windows Trust Store. Required for deep packet inspection.', font=(THEME['font_mono'], 11), text_color=THEME['text_muted']).pack(anchor='w', padx=25, pady=(0, 15))
        btn_frame = ctk.CTkFrame(ca_card, fg_color='transparent')
        btn_frame.pack(fill='x', padx=25, pady=(0, 20))
        ctk.CTkButton(btn_frame, text='[ INJECT CA ]', font=(THEME['font_mono'], 12, 'bold'), height=35, corner_radius=0, border_width=1, border_color=THEME['border'], fg_color=THEME['bg'], hover_color=THEME['border'], text_color=THEME['text_main'], command=self.do_install_ca).pack(side='left', padx=(0, 10))
        ctk.CTkButton(btn_frame, text='[ PURGE CA ]', font=(THEME['font_mono'], 12, 'bold'), height=35, corner_radius=0, border_width=1, border_color=THEME['border'], fg_color='transparent', hover_color=THEME['bg'], text_color=THEME['accent'], command=self.do_remove_ca).pack(side='left')
        deps_card = self.decorative_frame(scroll)
        deps_card.pack(fill='x', pady=(0, 15))
        ctk.CTkLabel(deps_card, text='// CORE MODULES', font=(THEME['font_mono'], 14, 'bold'), text_color=THEME['text_main']).pack(anchor='w', padx=25, pady=(20, 5))
        ctk.CTkLabel(deps_card, text='> Manage execution dependencies. Execute \'Purge\' to wipe app data and exit.', font=(THEME['font_mono'], 11), text_color=THEME['text_muted']).pack(anchor='w', padx=25, pady=(0, 15))
        btn_frame2 = ctk.CTkFrame(deps_card, fg_color='transparent')
        btn_frame2.pack(fill='x', padx=25, pady=(0, 20))
        self.btn_reinstall_deps = ctk.CTkButton(btn_frame2, text='[ REPAIR MODS ]', font=(THEME['font_mono'], 12, 'bold'), height=35, corner_radius=0, border_width=1, border_color=THEME['border'], fg_color=THEME['bg'], hover_color=THEME['border'], text_color=THEME['text_main'], command=self.do_reinstall_deps)
        self.btn_reinstall_deps.pack(side='left', padx=(0, 10))
        self.btn_delete_deps = ctk.CTkButton(btn_frame2, text='[ PURGE ALL ]', font=(THEME['font_mono'], 12, 'bold'), height=35, corner_radius=0, border_width=1, border_color=THEME['accent'], fg_color='transparent', hover_color=THEME['accent'], text_color=THEME['accent'], command=self.do_uninstall_deps)
        self.btn_delete_deps.pack(side='left')
        log_card = self.decorative_frame(scroll)
        log_card.pack(fill='x', pady=(0, 20))
        ctk.CTkLabel(log_card, text='// CONFIG.LOG', font=(THEME['font_mono'], 11, 'bold'), text_color=THEME['text_muted']).pack(anchor='w', padx=20, pady=(15, 0))
        self.sys_console = ctk.CTkTextbox(log_card, height=120, font=(THEME['font_mono'], 11), fg_color=THEME['bg'], corner_radius=0, text_color=THEME['text_muted'], border_width=1, border_color=THEME['border'])
        self.sys_console.pack(fill='both', expand=True, padx=20, pady=(10, 20))
        self.sys_console.insert('end', '> Sys Config loaded into memory.\n')
        self.sys_console.configure(state='disabled')
        return page
    def log_to_sys(self, msg):
        def update_ui():
            if hasattr(self, 'sys_console'):
                self.sys_console.configure(state='normal')
                self.sys_console.insert('end', f'> {msg}\n')
                self.sys_console.see('end')
                self.sys_console.configure(state='disabled')
        self.master.after(0, update_ui)
    def do_install_ca(self):
        self.log_to_sys('Attempting CA Injection...')
        if install_mitmproxy_cert():
            self.log_to_sys('[OK] Injection successful.')
            messagebox.showinfo('SYS.INFO', 'Root Certificate successfully injected!')
        else:
            self.log_to_sys('[ERR] Injection failed. Escalate to Admin.')
            messagebox.showerror('SYS.ERR', 'Injection Failed.\nPlease elevate privileges (Run as Admin).')
    def do_remove_ca(self):
        self.log_to_sys('Executing CA purge...')
        if remove_mitmproxy_cert():
            self.log_to_sys('[OK] CA purged.')
            messagebox.showinfo('SYS.INFO', 'Certificate removed securely.')
        else:
            self.log_to_sys('[!] CA not found or locked.')
    def do_reinstall_deps(self):
        self.btn_reinstall_deps.configure(state='disabled')
        self.log_to_sys('Rebuilding dependencies...')
        def task():
            try:
                kwargs = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
                subprocess.call([sys.executable, '-m', 'pip', 'install', '--force-reinstall'] + REQUIRED_PACKAGES, **kwargs)
                self.log_to_sys('[OK] Rebuild complete.')
            except:
                self.log_to_sys('[ERR] Rebuild interrupted.')
            self.master.after(0, lambda: self.btn_reinstall_deps.configure(state='normal'))
        Thread(target=task, daemon=True).start()
    def do_uninstall_deps(self):
        confirm = messagebox.askyesno('SYS.WARN', 'Executing this command will wipe all Python dependencies and shut down. Confirm?')
        if confirm:
            self.btn_delete_deps.configure(state='disabled')
            self.log_to_sys('Purging modules...')
            def task():
                kwargs = {'creationflags': subprocess.CREATE_NO_WINDOW} if sys.platform == 'win32' else {}
                subprocess.call([sys.executable, '-m', 'pip', 'uninstall', '-y'] + REQUIRED_PACKAGES, **kwargs)
                os._exit(0)
            Thread(target=task, daemon=True).start()
    def show_page(self, name):
        if not self.pages:
            self.create_main_page()
            self.create_how_page()
            self.create_sys_page()
        for p in self.pages.values():
            p.pack_forget()
        self.pages[name].pack(fill='both', expand=True)
        self.update_nav_active_state(name)
    def load_config(self):
        # irreducible cflow, using cdg fallback
        # ***<module>.NullMaskGUI.load_config: Failure: Compilation Error
        if os.path.exists(CONFIG_FILE_PATH):
            pass
        with open(CONFIG_FILE_PATH, 'r') as f:
            config = json.load(f)
            self.saved_name = config.get('last_spoof_name', 'Null')
            self.saved_key = config.get('license_key', '')
            return None
    def save_config(self):
        config = {'last_spoof_name': self.name_var.get() if hasattr(self, 'name_var') else self.saved_name, 'license_key': self.saved_key}
        with open(CONFIG_FILE_PATH, 'w') as f:
            json.dump(config, f)
    def toggle_proxy(self):
        if not self.is_proxy_running:
            if not is_mitmproxy_cert_installed():
                self.show_page('sys')
                messagebox.showwarning('SYS.WARN', 'CA Certificate not detected. Inject via SYS_CONFIG first.')
                return None
            else:
                self.log_to_console('OVERWRITING SYS.PROXY...')
                if set_system_proxy(MITMPROXY_LISTEN_HOST, MITMPROXY_LISTEN_PORT):
                    self.is_proxy_running = True
                    self.packets_injected = 0
                    self.toggle_btn.configure(text='HALT INJECTION', fg_color='transparent', border_width=1, border_color=THEME['accent'], text_color=THEME['accent'], hover_color=THEME['panel'])
                    self.entry.configure(state='disabled')
                    self.save_config()
                    Thread(target=run_mitmproxy_thread_target, args=(self.name_var.get(), self.log_to_console, self.increment_packets), daemon=True).start()
        else:
            self.log_to_console('RESTORING LOCAL ROUTING...')
            disable_system_proxy()
            if mitmproxy_master:
                mitmproxy_master.shutdown()
            self.is_proxy_running = False
            self.toggle_btn.configure(text='INITIATE OVERWRITE', fg_color=THEME['accent'], border_width=0, text_color='#FFFFFF', hover_color=THEME['accent_hover'])
            self.entry.configure(state='normal')
    def on_closing(self):
        disable_system_proxy()
        self.master.destroy()
        sys.exit(0)
if __name__ == '__main__':
    import multiprocessing
    multiprocessing.freeze_support()
    try:
        root = ctk.CTk() if DEPENDENCIES_OK else tk.Tk()
        app = NullMaskGUI(root)
        root.mainloop()
    except Exception as e:
        pass
    finally:
        disable_system_proxy()