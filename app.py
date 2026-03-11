import customtkinter as ctk
import sys
import os
import queue
import threading
from core import SecureDriveCore
import subprocess
import shutil
from PIL import Image

ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


def mac_font(size, weight="normal"):
    return ctk.CTkFont(
        family="San Francisco, Helvetica Neue, Helvetica, Arial",
        size=size,
        weight=weight,
    )


class LoggerModal(ctk.CTkToplevel):
    def __init__(self, master_app, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.master_app = master_app
        self.master_app.current_logger = self

        self.title("Cryptographic Handshake Logs")
        self.geometry("700x450")
        self.textbox = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="monospace", size=13),
            text_color="#30d158",
            fg_color="#1c1c1e",
        )
        self.textbox.pack(fill="both", expand=True, padx=15, pady=15)
        self.textbox.insert("end", master_app.log_history)
        self.textbox.yview("end")
        self.textbox.configure(state="disabled")

    def append_log(self, text):
        self.textbox.configure(state="normal")
        self.textbox.insert("end", text + "\n")
        self.textbox.yview("end")
        self.textbox.configure(state="disabled")


class PasswordModal(ctk.CTkToplevel):
    def __init__(self, *args, is_setup=False, callback=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.callback = callback
        self.is_setup = is_setup

        self.title("SecureDrive Authentication")
        self.geometry("380x240" if is_setup else "380x190")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.after(100, self.grab_set)

        self.update_idletasks()
        try:
            x = (
                self.master.winfo_x()
                + (self.master.winfo_width() // 2)
                - (self.winfo_width() // 2)
            )
            y = (
                self.master.winfo_y()
                + (self.master.winfo_height() // 2)
                - (self.winfo_height() // 2)
            )
            self.geometry(f"+{x}+{y}")
        except:
            pass

        self.label = ctk.CTkLabel(
            self,
            text="Vault Setup:" if is_setup else "Unlock SecureDrive",
            font=mac_font(15, "bold"),
        )
        self.label.pack(pady=(20, 10))

        self.password_entry = ctk.CTkEntry(
            self,
            placeholder_text="Password",
            show="*",
            width=260,
            height=36,
            corner_radius=8,
        )
        self.password_entry.pack(pady=5)
        self.password_entry.bind("<Return>", lambda e: self.submit())

        if self.is_setup:
            self.confirm_entry = ctk.CTkEntry(
                self,
                placeholder_text="Confirm Password",
                show="*",
                width=260,
                height=36,
                corner_radius=8,
            )
            self.confirm_entry.pack(pady=5)
            self.confirm_entry.bind("<Return>", lambda e: self.submit())
            self.warning_label = ctk.CTkLabel(
                self,
                text="Existing data will be entirely erased.",
                text_color="#ff453a",
                font=mac_font(11),
            )
            self.warning_label.pack(pady=2)

        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=(15, 0))

        self.cancel_btn = ctk.CTkButton(
            self.btn_frame,
            text="Cancel",
            fg_color="#3a3a3c",
            hover_color="#2c2c2e",
            command=self.cancel,
            width=110,
            height=32,
            corner_radius=16,
            font=mac_font(13),
        )
        self.cancel_btn.pack(side="left", padx=10)

        self.submit_btn = ctk.CTkButton(
            self.btn_frame,
            text="Unlock" if not is_setup else "Initialize",
            command=self.submit,
            width=110,
            height=32,
            corner_radius=16,
            font=mac_font(13, "bold"),
            fg_color="#0a84ff",
            hover_color="#0070e5",
        )
        self.submit_btn.pack(side="left", padx=10)

        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def submit(self):
        pwd = self.password_entry.get()
        if self.is_setup:
            cpwd = self.confirm_entry.get()
            if not pwd or pwd != cpwd:
                self.label.configure(text="Passwords mismatch!", text_color="#ff453a")
                return
            if self.callback:
                self.callback(pwd)
        else:
            if not pwd:
                return
            if self.callback:
                self.callback(pwd, False)
        self.destroy()

    def cancel(self):
        if self.callback:
            self.callback(None) if self.is_setup else self.callback(None, False)
        self.destroy()


class PromptModal(ctk.CTkToplevel):
    def __init__(self, title_text, label_text, callback, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.callback = callback
        self.title(title_text)
        self.geometry("380x180")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.after(100, self.grab_set)

        self.update_idletasks()
        try:
            x = (
                self.master.winfo_x()
                + (self.master.winfo_width() // 2)
                - (self.winfo_width() // 2)
            )
            y = (
                self.master.winfo_y()
                + (self.master.winfo_height() // 2)
                - (self.winfo_height() // 2)
            )
            self.geometry(f"+{x}+{y}")
        except:
            pass

        self.label = ctk.CTkLabel(self, text=label_text, font=mac_font(14, "bold"))
        self.label.pack(pady=(25, 10))

        self.entry = ctk.CTkEntry(self, width=280, height=36, corner_radius=8)
        self.entry.pack(pady=5)
        self.entry.focus_set()
        self.entry.bind("<Return>", lambda e: self.submit())

        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=(15, 0))

        self.cancel_btn = ctk.CTkButton(
            self.btn_frame,
            text="Cancel",
            fg_color="#3a3a3c",
            hover_color="#2c2c2e",
            command=self.cancel,
            width=100,
            height=32,
            corner_radius=16,
            font=mac_font(13),
        )
        self.cancel_btn.pack(side="left", padx=10)

        self.submit_btn = ctk.CTkButton(
            self.btn_frame,
            text="OK",
            command=self.submit,
            width=100,
            height=32,
            corner_radius=16,
            font=mac_font(13, "bold"),
            fg_color="#0a84ff",
            hover_color="#0070e5",
        )
        self.submit_btn.pack(side="left", padx=10)

        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def submit(self):
        val = self.entry.get().strip()
        if self.callback:
            self.callback(val)
        self.destroy()

    def cancel(self):
        if self.callback:
            self.callback(None)
        self.destroy()


class ChangePasswordModal(ctk.CTkToplevel):
    def __init__(self, master_app, callback, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.callback = callback
        self.title("Change SecureDrive Password")
        self.geometry("400x350")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.after(100, self.grab_set)

        self.update_idletasks()
        try:
            x = (
                self.master.winfo_x()
                + (self.master.winfo_width() // 2)
                - (self.winfo_width() // 2)
            )
            y = (
                self.master.winfo_y()
                + (self.master.winfo_height() // 2)
                - (self.winfo_height() // 2)
            )
            self.geometry(f"+{x}+{y}")
        except:
            pass

        self.label = ctk.CTkLabel(
            self, text="Change Password", font=mac_font(18, "bold")
        )
        self.label.pack(pady=(25, 10))

        self.err_lbl = ctk.CTkLabel(
            self, text="", text_color="#ff453a", font=mac_font(12)
        )
        self.err_lbl.pack(pady=0)

        self.old_entry = ctk.CTkEntry(
            self,
            width=280,
            height=36,
            corner_radius=8,
            show="*",
            placeholder_text="Current Password",
        )
        self.old_entry.pack(pady=10)
        self.old_entry.focus_set()

        self.new_entry = ctk.CTkEntry(
            self,
            width=280,
            height=36,
            corner_radius=8,
            show="*",
            placeholder_text="New Password",
        )
        self.new_entry.pack(pady=10)

        self.confirm_entry = ctk.CTkEntry(
            self,
            width=280,
            height=36,
            corner_radius=8,
            show="*",
            placeholder_text="Confirm New Password",
        )
        self.confirm_entry.pack(pady=10)
        self.confirm_entry.bind("<Return>", lambda e: self.submit())

        self.btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.btn_frame.pack(pady=(15, 0))

        self.cancel_btn = ctk.CTkButton(
            self.btn_frame,
            text="Cancel",
            fg_color="#3a3a3c",
            hover_color="#2c2c2e",
            command=self.cancel,
            width=100,
            height=32,
            corner_radius=16,
            font=mac_font(13),
        )
        self.cancel_btn.pack(side="left", padx=10)

        self.submit_btn = ctk.CTkButton(
            self.btn_frame,
            text="Change",
            command=self.submit,
            width=100,
            height=32,
            corner_radius=16,
            font=mac_font(13, "bold"),
            fg_color="#ff9f0a",
            hover_color="#d08a10",
        )
        self.submit_btn.pack(side="left", padx=10)

        self.protocol("WM_DELETE_WINDOW", self.cancel)

    def submit(self):
        old_pwd = self.old_entry.get().strip()
        new_pwd = self.new_entry.get().strip()
        confirm_pwd = self.confirm_entry.get().strip()

        if not old_pwd or not new_pwd:
            self.err_lbl.configure(text="All fields are required.")
            return
        if new_pwd != confirm_pwd:
            self.err_lbl.configure(text="New passwords do not match.")
            return

        if self.callback:
            self.submit_btn.configure(state="disabled", text="Working...")
            self.update_idletasks()
            self.callback(old_pwd, new_pwd, self)

    def cancel(self):
        self.destroy()


class SetupAssistant(ctk.CTkToplevel):
    def __init__(self, master_app, drives_list, callback, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.master_app = master_app
        self.callback = callback

        self.title("SecureDrive Provisioning Assistant")
        self.geometry("650x450")
        self.resizable(False, False)
        self.attributes("-topmost", True)
        self.after(100, self.grab_set)

        self.update_idletasks()
        try:
            x = (
                self.master.winfo_x()
                + (self.master.winfo_width() // 2)
                - (self.winfo_width() // 2)
            )
            y = (
                self.master.winfo_y()
                + (self.master.winfo_height() // 2)
                - (self.winfo_height() // 2)
            )
            self.geometry(f"+{x}+{y}")
        except:
            pass

        # Clean Split view
        self.sidebar = ctk.CTkFrame(
            self, width=200, corner_radius=0, fg_color="#1c1c1e"
        )
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        ctk.CTkLabel(self.sidebar, text="Provisioning", font=mac_font(20, "bold")).pack(
            pady=(30, 20), padx=20, anchor="w"
        )
        self.step1_lbl = ctk.CTkLabel(
            self.sidebar,
            text="1. Select Drive",
            font=mac_font(14, "bold"),
            text_color="#0a84ff",
        )
        self.step1_lbl.pack(pady=10, padx=20, anchor="w")
        self.step2_lbl = ctk.CTkLabel(
            self.sidebar, text="2. Security", font=mac_font(14), text_color="#8e8e93"
        )
        self.step2_lbl.pack(pady=10, padx=20, anchor="w")

        self.content = ctk.CTkFrame(self, fg_color="#2c2c2e", corner_radius=0)
        self.content.pack(side="right", fill="both", expand=True)

        self.drive_var = ctk.StringVar()
        self.drives = drives_list
        self.build_step1()

    def build_step1(self):
        for widget in self.content.winfo_children():
            widget.destroy()
        self.step1_lbl.configure(text_color="#0a84ff", font=mac_font(14, "bold"))
        self.step2_lbl.configure(text_color="#8e8e93", font=mac_font(14))

        ctk.CTkLabel(
            self.content, text="Select Target Drive", font=mac_font(24, "bold")
        ).pack(pady=(40, 10), anchor="w", padx=40)
        ctk.CTkLabel(
            self.content,
            text="Warning: The selected drive will be permanently erased.",
            text_color="#ff453a",
            font=mac_font(13),
        ).pack(anchor="w", padx=40, pady=(0, 20))

        if not self.drives:
            ctk.CTkLabel(
                self.content, text="No external USB drives found.", font=mac_font(14)
            ).pack(pady=40)
            ctk.CTkButton(
                self.content,
                text="Cancel",
                command=self.destroy,
                width=100,
                corner_radius=16,
            ).pack(pady=20)
            return

        self.drive_var.set(self.drives[0]["node"])
        for drv in self.drives:
            rb = ctk.CTkRadioButton(
                self.content,
                text=f"{drv['model']} ({drv['size_gb']} GB)  [{drv['node']}]",
                variable=self.drive_var,
                value=drv["node"],
                font=mac_font(14),
            )
            rb.pack(pady=8, padx=40, anchor="w")

        btn_box = ctk.CTkFrame(self.content, fg_color="transparent")
        btn_box.pack(side="bottom", fill="x", pady=30, padx=40)
        ctk.CTkButton(
            btn_box,
            text="Cancel",
            fg_color="#3a3a3c",
            hover_color="#2c2c2e",
            command=self.destroy,
            width=100,
            height=32,
            corner_radius=16,
        ).pack(side="left")
        ctk.CTkButton(
            btn_box,
            text="Continue",
            fg_color="#0a84ff",
            command=self.build_step2,
            width=100,
            height=32,
            corner_radius=16,
        ).pack(side="right")

    def build_step2(self):
        for widget in self.content.winfo_children():
            widget.destroy()
        self.step1_lbl.configure(text_color="#8e8e93", font=mac_font(14))
        self.step2_lbl.configure(text_color="#0a84ff", font=mac_font(14, "bold"))

        ctk.CTkLabel(
            self.content, text="Securing Vault", font=mac_font(24, "bold")
        ).pack(pady=(40, 10), anchor="w", padx=40)
        ctk.CTkLabel(
            self.content,
            text="Create a master password for this Zero-Trust drive.",
            font=mac_font(13),
        ).pack(anchor="w", padx=40, pady=(0, 20))

        self.pwd_entry = ctk.CTkEntry(
            self.content,
            placeholder_text="New Password",
            show="*",
            width=300,
            height=40,
            corner_radius=8,
        )
        self.pwd_entry.pack(pady=10, padx=40, anchor="w")

        self.cpwd_entry = ctk.CTkEntry(
            self.content,
            placeholder_text="Verify Password",
            show="*",
            width=300,
            height=40,
            corner_radius=8,
        )
        self.cpwd_entry.pack(pady=10, padx=40, anchor="w")

        self.err_lbl = ctk.CTkLabel(self.content, text="", text_color="#ff453a")
        self.err_lbl.pack(anchor="w", padx=40)

        btn_box = ctk.CTkFrame(self.content, fg_color="transparent")
        btn_box.pack(side="bottom", fill="x", pady=30, padx=40)
        ctk.CTkButton(
            btn_box,
            text="Back",
            fg_color="#3a3a3c",
            hover_color="#2c2c2e",
            command=self.build_step1,
            width=100,
            height=32,
            corner_radius=16,
        ).pack(side="left")
        ctk.CTkButton(
            btn_box,
            text="Erase & Format",
            fg_color="#ff453a",
            text_color="white",
            hover_color="#d70015",
            command=self.finalize,
            width=130,
            height=32,
            corner_radius=16,
            font=mac_font(13, "bold"),
        ).pack(side="right")

    def finalize(self):
        p1 = self.pwd_entry.get()
        if not p1 or p1 != self.cpwd_entry.get():
            self.err_lbl.configure(text="Passwords do not match.")
            return
        if self.callback:
            self.callback(self.drive_var.get(), p1)
        self.destroy()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        if os.geteuid() != 0:
            print("ERROR: SecureDrive must be run as root (sudo).")
            print(
                'To run the GUI as root in Wayland/X11, consider: sudo -E env "PATH=$PATH" python app.py'
            )
            sys.exit(1)

        self.title("SecureDrive")
        self.geometry("900x600")
        self.minsize(850, 550)
        self.resizable(True, True)

        # macOS style layout
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # 1. Sidebar (Translucent Dark style)
        self.sidebar = ctk.CTkFrame(
            self, width=220, corner_radius=0, fg_color="#1c1c1e"
        )
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_propagate(False)

        ctk.CTkLabel(self.sidebar, text="SecureDrive", font=mac_font(20, "bold")).pack(
            pady=(35, 30), padx=20, anchor="w"
        )

        # Sidebar navigation pills
        self.nav_vault_btn = ctk.CTkButton(
            self.sidebar,
            text="Vault Dashboard",
            fg_color="#2c2c2e",
            text_color="white",
            hover_color="#3a3a3c",
            corner_radius=8,
            height=36,
            font=mac_font(14),
            command=self.show_dashboard,
            anchor="w",
        )
        self.nav_vault_btn.pack(padx=15, pady=5, fill="x")

        self.nav_prov_btn = ctk.CTkButton(
            self.sidebar,
            text="Provision Drive",
            fg_color="transparent",
            text_color="#8e8e93",
            hover_color="#2c2c2e",
            corner_radius=8,
            height=36,
            font=mac_font(14),
            command=self.open_provision,
            anchor="w",
        )
        self.nav_prov_btn.pack(padx=15, pady=5, fill="x")

        self.nav_cpwd_btn = ctk.CTkButton(
            self.sidebar,
            text="Change Password",
            fg_color="transparent",
            text_color="#8e8e93",
            hover_color="#2c2c2e",
            corner_radius=8,
            height=36,
            font=mac_font(14),
            command=self.open_change_password,
            anchor="w",
        )
        self.nav_cpwd_btn.pack(padx=15, pady=5, fill="x")

        # Hidden log viewer launcher
        self.log_launcher = ctk.CTkButton(
            self.sidebar,
            text="View Setup Logs",
            fg_color="transparent",
            text_color="#8e8e93",
            hover_color="#2c2c2e",
            command=self.show_logs,
            anchor="w",
            font=mac_font(12),
        )
        self.log_launcher.pack(side="bottom", pady=20, padx=15, fill="x")

        # 2. Main Content Area
        self.main_content = ctk.CTkFrame(self, fg_color="#2c2c2e", corner_radius=0)
        self.main_content.grid(row=0, column=1, sticky="nsew")
        self.main_content.grid_rowconfigure(0, weight=1)
        self.main_content.grid_columnconfigure(0, weight=1)

        #   A. Hero Status View (When Locked/Waiting)
        self.hero_view = ctk.CTkFrame(self.main_content, fg_color="transparent")
        self.hero_view.grid(row=0, column=0, sticky="nsew")

        self.hero_icon = ctk.CTkLabel(
            self.hero_view,
            text="SECUREDRIVE",
            font=mac_font(40, "bold"),
            text_color="#3a3a3c",
        )
        self.hero_icon.pack(expand=True, pady=(120, 0))

        self.hero_status = ctk.CTkLabel(
            self.hero_view,
            text="Waiting for USB...",
            font=mac_font(22, "bold"),
            text_color="#8e8e93",
        )
        self.hero_status.pack(pady=(0, 20))

        self.hero_subtext = ctk.CTkLabel(
            self.hero_view,
            text="Insert a SecureDrive passport to begin.",
            font=mac_font(15),
            text_color="#8e8e93",
        )
        self.hero_subtext.pack(expand=True, anchor="n")

        #   B. File Manager View (When Unlocked)
        self.fm_view = ctk.CTkFrame(self.main_content, fg_color="transparent")
        # fm_view is NOT gridded initially. Only shown when UNLOCKED.

        # File Manager Header
        fm_header = ctk.CTkFrame(self.fm_view, height=80, fg_color="transparent")
        fm_header.pack(fill="x", pady=(30, 10), padx=40)

        ctk.CTkLabel(fm_header, text="Vault Contents", font=mac_font(28, "bold")).pack(
            side="left"
        )

        ctk.CTkButton(
            fm_header,
            text="Terminal",
            width=90,
            height=36,
            corner_radius=18,
            fg_color="#3a3a3c",
            hover_color="#48484a",
            command=self.open_terminal,
            font=mac_font(13, "bold"),
        ).pack(side="right", padx=8)
        ctk.CTkButton(
            fm_header,
            text="Open in System",
            width=120,
            height=36,
            corner_radius=18,
            fg_color="#3a3a3c",
            hover_color="#48484a",
            command=self.reveal_in_finder,
            font=mac_font(13, "bold"),
        ).pack(side="right", padx=8)
        ctk.CTkButton(
            fm_header,
            text="New Folder",
            width=100,
            height=36,
            corner_radius=18,
            fg_color="#3a3a3c",
            hover_color="#48484a",
            command=self.create_new_folder,
            font=mac_font(13, "bold"),
        ).pack(side="right", padx=8)
        ctk.CTkButton(
            fm_header,
            text="New File",
            width=90,
            height=36,
            corner_radius=18,
            fg_color="#3a3a3c",
            hover_color="#48484a",
            command=self.create_new_file,
            font=mac_font(13, "bold"),
        ).pack(side="right", padx=8)
        ctk.CTkButton(
            fm_header,
            text="Refresh",
            width=80,
            height=36,
            corner_radius=18,
            fg_color="#2c2c2e",
            hover_color="#3a3a3c",
            text_color="#8e8e93",
            command=lambda: self.refresh_fm(manual=True),
            font=mac_font(13),
        ).pack(side="right", padx=8)

        # File Manager List Header (Name, Kind, Action)
        fm_cols = ctk.CTkFrame(self.fm_view, height=30, fg_color="#2c2c2e")
        fm_cols.pack(fill="x", padx=45)
        ctk.CTkLabel(
            fm_cols,
            text="NAME",
            font=mac_font(11, "bold"),
            text_color="#8e8e93",
            width=280,
            anchor="w",
        ).pack(side="left", padx=15)
        ctk.CTkLabel(
            fm_cols,
            text="KIND",
            font=mac_font(11, "bold"),
            text_color="#8e8e93",
            width=80,
            anchor="w",
        ).pack(side="left", padx=10)
        ctk.CTkLabel(
            fm_cols,
            text="SIZE",
            font=mac_font(11, "bold"),
            text_color="#8e8e93",
            width=80,
            anchor="w",
        ).pack(side="left", padx=10)
        ctk.CTkLabel(
            fm_cols,
            text="ACTIONS",
            font=mac_font(11, "bold"),
            text_color="#8e8e93",
            anchor="e",
        ).pack(side="right", padx=50)

        ctk.CTkFrame(self.fm_view, height=1, fg_color="#3a3a3c").pack(
            fill="x", padx=35, pady=5
        )  # Divider

        self.fm_list = ctk.CTkScrollableFrame(self.fm_view, fg_color="transparent")
        self.fm_list.pack(fill="both", expand=True, padx=20, pady=(0, 20))

        # Infrastructure
        self.log_history = ""
        self.hero_anim_id = None
        self.hero_anim_frame = 0
        self.ui_queue = queue.Queue()
        self.check_queue()

        self.core = SecureDriveCore(
            on_log=self.handle_log_event,
            on_status=self.handle_status_event,
            on_password_requested=self.handle_password_requested,
            on_setup_requested=self.handle_setup_requested,
        )
        self.core.start()

    def show_dashboard(self):
        # Reset sidebar nav highlights
        self.nav_vault_btn.configure(fg_color="#2c2c2e", text_color="white")

    def show_logs(self):
        LoggerModal(self)

    def check_queue(self):
        try:
            while True:
                task = self.ui_queue.get_nowait()
                cmd = task[0]
                if cmd == "log":
                    self.log_history += task[1] + "\n"
                    if (
                        hasattr(self, "current_logger")
                        and self.current_logger
                        and self.current_logger.winfo_exists()
                    ):
                        self.current_logger.append_log(task[1])
                elif cmd == "status":
                    self.update_status_ui(task[1])
                elif cmd == "password":
                    cb = task[1]
                    PasswordModal(self, is_setup=False, callback=cb)
                elif cmd == "setup":
                    cb = task[1]
                    PasswordModal(self, is_setup=True, callback=cb)
        except queue.Empty:
            pass
        finally:
            self.after(100, self.check_queue)

    def handle_log_event(self, msg):
        self.ui_queue.put(("log", msg))

    def handle_status_event(self, stat):
        self.ui_queue.put(("status", stat))

    def handle_password_requested(self, callback):
        self.ui_queue.put(("password", callback))

    def handle_setup_requested(self, callback):
        self.ui_queue.put(("setup", callback))

    def animate_hero(self):
        if not self.hero_view.winfo_ismapped():
            self.hero_anim_id = None
            return

        self.hero_anim_frame = (self.hero_anim_frame + 1) % 4
        dots = "." * self.hero_anim_frame

        current_text = self.hero_status.cget("text").rstrip(".")
        if "Waiting" in current_text or "Authorizing" in current_text:
            self.hero_status.configure(text=f"{current_text}{dots}")

        self.hero_anim_id = self.after(500, self.animate_hero)

    def update_status_ui(self, stat):
        # Swap between Hero and FM views
        if stat == "UNLOCKED":
            if self.hero_anim_id:
                self.after_cancel(self.hero_anim_id)
                self.hero_anim_id = None
            self.hero_view.grid_forget()
            self.fm_view.pack(fill="both", expand=True)
            self.refresh_fm()
        else:
            self.fm_view.pack_forget()
            self.hero_view.grid(row=0, column=0, sticky="nsew")

            if stat == "WAITING":
                self.hero_icon.configure(text="LOCKED", text_color="#3a3a3c")
                self.hero_status.configure(text="Waiting for USB", text_color="#8e8e93")
                self.hero_subtext.configure(
                    text="Insert a SecureDrive passport to begin."
                )
            elif stat == "PHASE1":
                self.hero_icon.configure(text="AUTHORIZING", text_color="#0a84ff")
                self.hero_status.configure(text="Verifying Device", text_color="white")
                self.hero_subtext.configure(
                    text="Performing Zero-Trust Anti-Cloning check..."
                )
            elif stat == "PHASE2":
                self.hero_icon.configure(text="SECURED", text_color="#f39c12")
                self.hero_status.configure(text="Awaiting Password", text_color="white")
                self.hero_subtext.configure(text="Please enter vault credentials.")
            elif stat == "ERROR":
                self.hero_icon.configure(text="DENIED", text_color="#ff453a")
                self.hero_status.configure(
                    text="Authentication Failed", text_color="#ff453a"
                )
                self.hero_subtext.configure(
                    text="Access denied or device error. Please remove drive."
                )
                if self.hero_anim_id:
                    self.after_cancel(self.hero_anim_id)
                    self.hero_anim_id = None

            if stat in ["WAITING", "PHASE1"] and not self.hero_anim_id:
                self.animate_hero()

    def open_provision(self):
        drives = self.core.get_available_usb_drives()
        SetupAssistant(self, drives, self.start_provisioning)

    def start_provisioning(self, device_node, password):
        def task():
            self.core.provision_usb_drive(device_node, password)

        threading.Thread(target=task, daemon=True).start()

    def open_change_password(self):
        def on_change(old_pw, new_pw, modal):
            def task():
                self.core.log("[*] Waiting for backend to re-wrap keys...")
                success = self.core.change_password(old_pw, new_pw)
                if success:
                    self.after(0, modal.destroy)
                else:
                    self.after(
                        0,
                        lambda: modal.submit_btn.configure(
                            state="normal", text="Change"
                        ),
                    )
                    self.after(
                        0,
                        lambda: modal.err_lbl.configure(
                            text="Failed to change password. Validate old password."
                        ),
                    )

            threading.Thread(target=task, daemon=True).start()

        ChangePasswordModal(self, on_change)

    # --- File Manager Methods ---
    def refresh_fm(self, manual=False):
        for widget in self.fm_list.winfo_children():
            widget.destroy()

        base_path = "/mnt/unlocked_vault"
        if not os.path.exists(base_path):
            return

        try:
            items = os.listdir(base_path)
        except PermissionError:
            return

        if not items:
            ctk.CTkLabel(
                self.fm_list,
                text="Folder is Empty",
                text_color="#8e8e93",
                font=mac_font(14),
            ).pack(pady=60)
            return

        for idx, item in enumerate(sorted(items)):
            f_path = os.path.join(base_path, item)
            is_dir = os.path.isdir(f_path)

            # Subtle alternating row colors for data-table feel
            bg_color = "#2c2c2e" if idx % 2 == 0 else "transparent"
            row = ctk.CTkFrame(self.fm_list, fg_color=bg_color, corner_radius=6)
            row.pack(fill="x", pady=2, padx=10)

            # Name Column
            name_lbl = ctk.CTkLabel(
                row,
                text=f"  {item}",
                font=mac_font(13, "bold" if is_dir else "normal"),
                width=280,
                anchor="w",
            )
            name_lbl.pack(side="left", padx=5, pady=6)

            # Kind Column
            kind_txt = "Folder" if is_dir else "Document"
            kind_clr = "#0a84ff" if is_dir else "#8e8e93"
            ctk.CTkLabel(
                row,
                text=kind_txt,
                text_color=kind_clr,
                font=mac_font(12),
                width=80,
                anchor="w",
            ).pack(side="left", padx=10)

            # Size Column
            size_str = "--"
            if not is_dir:
                try:
                    sz = os.path.getsize(f_path)
                    size_str = (
                        f"{sz / 1024:.1f} KB"
                        if sz < 1024 * 1024
                        else f"{sz / (1024*1024):.1f} MB"
                    )
                except:
                    pass
            ctk.CTkLabel(
                row,
                text=size_str,
                text_color="#8e8e93",
                font=mac_font(12),
                width=80,
                anchor="w",
            ).pack(side="left", padx=10)

            def make_open_func(p=f_path):
                def wrapper():
                    u = os.environ.get("SUDO_USER")
                    c = ["sudo", "-E", "-u", u, "xdg-open", p] if u else ["xdg-open", p]
                    subprocess.Popen(c)

                return wrapper

            def make_rename_func(p=f_path, old_n=item):
                return lambda: self.rename_item(p, old_n)

            def make_del_func(p=f_path, d=is_dir):
                return lambda: self.delete_item(p, d)

            actions = ctk.CTkFrame(row, fg_color="transparent")
            actions.pack(side="right", padx=5, pady=4)

            # Minimalist Action Buttons
            ctk.CTkButton(
                actions,
                text="Rename",
                width=50,
                height=24,
                corner_radius=4,
                fg_color="transparent",
                text_color="#0a84ff",
                font=mac_font(11, "bold"),
                hover_color="#3a3a3c",
                command=make_rename_func(),
            ).pack(side="left", padx=2)
            ctk.CTkButton(
                actions,
                text="Delete",
                width=50,
                height=24,
                corner_radius=4,
                fg_color="transparent",
                text_color="#ff453a",
                font=mac_font(11, "bold"),
                hover_color="#48484a",
                command=make_del_func(),
            ).pack(side="left", padx=2)
            ctk.CTkButton(
                actions,
                text="Open",
                width=60,
                height=24,
                corner_radius=6,
                font=mac_font(11, "bold"),
                fg_color="#3a3a3c",
                text_color="white",
                hover_color="#48484a",
                command=make_open_func(),
            ).pack(side="right", padx=10)

    def create_new_folder(self):
        def on_name(name):
            if name:
                path = os.path.join("/mnt/unlocked_vault", name)
                try:
                    os.makedirs(path, exist_ok=True)
                    self.refresh_fm()
                except Exception as e:
                    print(e)

        PromptModal("New Folder", "Folder Name:", on_name, master=self)

    def rename_item(self, path, old_name):
        def on_name(new_name):
            if new_name and new_name != old_name:
                new_path = os.path.join("/mnt/unlocked_vault", new_name)
                try:
                    os.rename(path, new_path)
                    self.refresh_fm()
                except Exception as e:
                    print(e)

        PromptModal("Rename", f"Rename '{old_name}' to:", on_name, master=self)

    def delete_item(self, path, is_dir):
        msg = f"Are you sure you want to permanently delete this {'folder' if is_dir else 'file'}?"
        dialog = ctk.CTkToplevel(self)
        dialog.title("Confirm Delete")
        dialog.geometry("400x150")
        dialog.attributes("-topmost", True)

        try:
            x = self.winfo_x() + (self.winfo_width() // 2) - 200
            y = self.winfo_y() + (self.winfo_height() // 2) - 75
            dialog.geometry(f"+{x}+{y}")
        except:
            pass

        ctk.CTkLabel(dialog, text=msg, font=mac_font(13), wraplength=350).pack(pady=30)

        def confirm():
            try:
                shutil.rmtree(path) if is_dir else os.remove(path)
                self.refresh_fm()
            except Exception as e:
                print(e)
            dialog.destroy()

        btn_box = ctk.CTkFrame(dialog, fg_color="transparent")
        btn_box.pack(side="bottom", fill="x", pady=20, padx=20)
        ctk.CTkButton(
            btn_box,
            text="Cancel",
            command=dialog.destroy,
            fg_color="#3a3a3c",
            width=100,
            corner_radius=16,
        ).pack(side="left", padx=20)
        ctk.CTkButton(
            btn_box,
            text="Delete",
            command=confirm,
            fg_color="#ff453a",
            hover_color="#d70015",
            width=100,
            corner_radius=16,
        ).pack(side="right", padx=20)

    def create_new_file(self):
        def on_name(filename):
            if filename:
                path = os.path.join("/mnt/unlocked_vault", filename)
                try:
                    open(path, "w").close()
                    self.refresh_fm()
                except Exception as e:
                    print(e)

        PromptModal("New File", "Filename:", on_name, master=self)

    def open_terminal(self):
        path = "/mnt/unlocked_vault"
        user = os.environ.get("SUDO_USER")
        for term_cmd in [
            ["gnome-terminal", "--working-directory", path],
            ["konsole", "--workdir", path],
            ["xfce4-terminal", "--working-directory", path],
            ["alacritty", "--working-directory", path],
        ]:
            if (
                subprocess.run(
                    ["which", term_cmd[0]], stdout=subprocess.DEVNULL
                ).returncode
                == 0
            ):
                # Use -E to preserve DBUS_SESSION_BUS_ADDRESS so gnome-terminal can talk to the user's desktop session
                cmd = ["sudo", "-E", "-u", user] + term_cmd if user else term_cmd
                try:
                    subprocess.Popen(cmd)
                except:
                    pass
                return

    def reveal_in_finder(self):
        if os.path.exists("/mnt/unlocked_vault"):
            u = os.environ.get("SUDO_USER")
            c = (
                ["sudo", "-E", "-u", u, "xdg-open", "/mnt/unlocked_vault"]
                if u
                else ["xdg-open", "/mnt/unlocked_vault"]
            )
            subprocess.Popen(c)

    def on_closing(self):
        self.core.stop()
        self.destroy()


if __name__ == "__main__":
    app = App()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    app.mainloop()
