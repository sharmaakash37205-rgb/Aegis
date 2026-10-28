import os
import sys
import time
import secrets
import string
import threading
import subprocess
from typing import Optional
import tkinter as tk
from tkinter import filedialog, messagebox
import customtkinter as ctk

import crypto_engine

# Theme Configuration
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

COLOR_BG = "#0f172a"          # Slate 900
COLOR_CARD = "#1e293b"        # Slate 800
COLOR_CARD_BORDER = "#334155" # Slate 700
COLOR_ACCENT_ENCRYPT = "#0284c7" # Cyan / Sky Blue
COLOR_ACCENT_DECRYPT = "#10b981" # Emerald Green
COLOR_TEXT_MUTED = "#94a3b8"  # Slate 400

class ModernCryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()

        self.title("Aegis Vault — Military-Grade File Encryption (AES-256-GCM)")
        self.geometry("640x740")
        self.minsize(580, 700)
        self.configure(fg_color=COLOR_BG)

        # Set Window and Taskbar Icon
        icon_path = os.path.join(os.path.dirname(__file__), "assets", "app_icon.ico")
        if os.path.exists(icon_path):
            try:
                self.iconbitmap(icon_path)
            except Exception:
                pass

        # Application State
        self.selected_file_path = tk.StringVar()
        self.password_var = tk.StringVar()
        self.is_password_visible = False
        self.is_processing = False
        self.last_output_path = ""
        self.start_time = 0.0

        self._build_ui()
        self._on_password_change()

    def _build_ui(self):
        # Main Scrollable Container
        self.main_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        self.main_frame.pack(fill="both", expand=True, padx=20, pady=20)

        # 1. Header Section
        header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        header_frame.pack(fill="x", pady=(0, 15))

        title_badge = ctk.CTkLabel(
            header_frame,
            text="🛡️  AEGIS VAULT",
            font=ctk.CTkFont(family="Segoe UI", size=24, weight="bold"),
            text_color="#f8fafc",
        )
        title_badge.pack(anchor="w")

        subtitle = ctk.CTkLabel(
            header_frame,
            text="Zero-Knowledge AES-256-GCM Streaming Encryption • PBKDF2 600K Iterations",
            font=ctk.CTkFont(family="Segoe UI", size=12),
            text_color=COLOR_TEXT_MUTED,
        )
        subtitle.pack(anchor="w", pady=(2, 0))

        # 2. Mode Selector
        self.mode_selector = ctk.CTkSegmentedButton(
            self.main_frame,
            values=["🔒 Encrypt File", "🔓 Decrypt File"],
            command=self._on_mode_change,
            font=ctk.CTkFont(size=13, weight="bold"),
            height=38,
            selected_color=COLOR_ACCENT_ENCRYPT,
            selected_hover_color="#0369a1",
        )
        self.mode_selector.set("🔒 Encrypt File")
        self.mode_selector.pack(fill="x", pady=(0, 15))

        # 3. Target File Card
        self.file_card = ctk.CTkFrame(
            self.main_frame,
            fg_color=COLOR_CARD,
            border_color=COLOR_CARD_BORDER,
            border_width=1,
            corner_radius=12,
        )
        self.file_card.pack(fill="x", pady=(0, 15), ipady=5)

        file_header = ctk.CTkLabel(
            self.file_card,
            text="📁  Target File",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#f1f5f9",
        )
        file_header.pack(anchor="w", padx=16, pady=(12, 6))

        file_row = ctk.CTkFrame(self.file_card, fg_color="transparent")
        file_row.pack(fill="x", padx=16, pady=(0, 8))

        self.file_entry = ctk.CTkEntry(
            file_row,
            textvariable=self.selected_file_path,
            placeholder_text="Choose or enter a file path...",
            font=ctk.CTkFont(size=12),
            height=36,
        )
        self.file_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.file_entry.bind("<KeyRelease>", lambda e: self._update_file_info())

        self.browse_btn = ctk.CTkButton(
            file_row,
            text="Browse...",
            width=90,
            height=36,
            command=self._browse_file,
            font=ctk.CTkFont(weight="bold"),
        )
        self.browse_btn.pack(side="right")

        self.file_info_lbl = ctk.CTkLabel(
            self.file_card,
            text="No file selected (O(1) streaming supports files of any size)",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_MUTED,
        )
        self.file_info_lbl.pack(anchor="w", padx=16, pady=(0, 10))

        # 4. Passphrase & Security Card
        self.pass_card = ctk.CTkFrame(
            self.main_frame,
            fg_color=COLOR_CARD,
            border_color=COLOR_CARD_BORDER,
            border_width=1,
            corner_radius=12,
        )
        self.pass_card.pack(fill="x", pady=(0, 15), ipady=5)

        pass_header = ctk.CTkLabel(
            self.pass_card,
            text="  Security Passphrase",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#f1f5f9",
        )
        pass_header.pack(anchor="w", padx=16, pady=(12, 6))

        pass_row = ctk.CTkFrame(self.pass_card, fg_color="transparent")
        pass_row.pack(fill="x", padx=16, pady=(0, 8))

        self.pass_entry = ctk.CTkEntry(
            pass_row,
            textvariable=self.password_var,
            placeholder_text="Enter strong passphrase or generate one...",
            show="•",
            font=ctk.CTkFont(size=13),
            height=36,
        )
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 6))
        self.password_var.trace_add("write", lambda *args: self._on_password_change())

        self.show_pass_btn = ctk.CTkButton(
            pass_row,
            text="Show",
            width=40,
            height=36,
            fg_color="#334155",
            hover_color="#475569",
            command=self._toggle_password_visibility,
        )
        self.show_pass_btn.pack(side="left", padx=(0, 6))

        self.gen_pass_btn = ctk.CTkButton(
            pass_row,
            text=" Generate",
            width=90,
            height=36,
            fg_color="#4338ca",
            hover_color="#3730a3",
            command=self._generate_secure_password,
            font=ctk.CTkFont(weight="bold"),
        )
        self.gen_pass_btn.pack(side="right")

        # Password Strength Bar
        strength_row = ctk.CTkFrame(self.pass_card, fg_color="transparent")
        strength_row.pack(fill="x", padx=16, pady=(0, 10))

        self.strength_bar = ctk.CTkProgressBar(strength_row, height=6, corner_radius=3)
        self.strength_bar.pack(side="left", fill="x", expand=True, padx=(0, 10))
        self.strength_bar.set(0)

        self.strength_lbl = ctk.CTkLabel(
            strength_row,
            text="Strength: None",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_MUTED,
            width=130,
            anchor="e",
        )
        self.strength_lbl.pack(side="right")

        # 5. Progress & Live Telemetry Card
        self.telemetry_card = ctk.CTkFrame(
            self.main_frame,
            fg_color=COLOR_CARD,
            border_color=COLOR_CARD_BORDER,
            border_width=1,
            corner_radius=12,
        )
        self.telemetry_card.pack(fill="x", pady=(0, 15), ipady=5)

        telemetry_header_row = ctk.CTkFrame(self.telemetry_card, fg_color="transparent")
        telemetry_header_row.pack(fill="x", padx=16, pady=(12, 6))

        self.status_title_lbl = ctk.CTkLabel(
            telemetry_header_row,
            text=" Status: Ready",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#38bdf8",
        )
        self.status_title_lbl.pack(side="left")

        self.percent_lbl = ctk.CTkLabel(
            telemetry_header_row,
            text="0%",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#f8fafc",
        )
        self.percent_lbl.pack(side="right")

        self.progress_bar = ctk.CTkProgressBar(self.telemetry_card, height=10, corner_radius=5)
        self.progress_bar.pack(fill="x", padx=16, pady=(0, 8))
        self.progress_bar.set(0)

        self.metrics_lbl = ctk.CTkLabel(
            self.telemetry_card,
            text="Waiting for operation...",
            font=ctk.CTkFont(size=11),
            text_color=COLOR_TEXT_MUTED,
        )
        self.metrics_lbl.pack(anchor="w", padx=16, pady=(0, 10))

        # 6. Action Button
        self.execute_btn = ctk.CTkButton(
            self.main_frame,
            text="🔒  Encrypt File to .vault",
            font=ctk.CTkFont(size=15, weight="bold"),
            height=46,
            corner_radius=10,
            fg_color=COLOR_ACCENT_ENCRYPT,
            hover_color="#0369a1",
            command=self._start_processing,
        )
        self.execute_btn.pack(fill="x", pady=(0, 15))

        # 7. Result Feedback / Quick Actions Card (Hidden initially)
        self.result_card = ctk.CTkFrame(
            self.main_frame,
            fg_color="#064e3b",
            border_color="#059669",
            border_width=1,
            corner_radius=12,
        )
        # Will pack on completion

        self.result_lbl = ctk.CTkLabel(
            self.result_card,
            text="✅ Operation Successful",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#a7f3d0",
        )
        self.result_lbl.pack(anchor="w", padx=16, pady=(10, 4))

        self.result_path_lbl = ctk.CTkLabel(
            self.result_card,
            text="",
            font=ctk.CTkFont(size=11),
            text_color="#e2e8f0",
            wraplength=480,
            justify="left",
        )
        self.result_path_lbl.pack(anchor="w", padx=16, pady=(0, 8))

        result_actions_row = ctk.CTkFrame(self.result_card, fg_color="transparent")
        result_actions_row.pack(fill="x", padx=16, pady=(0, 10))

        self.copy_btn = ctk.CTkButton(
            result_actions_row,
            text=" Copy Path",
            width=100,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#047857",
            hover_color="#065f46",
            command=self._copy_result_path,
        )
        self.copy_btn.pack(side="left", padx=(0, 8))

        self.view_btn = ctk.CTkButton(
            result_actions_row,
            text=" View File",
            width=100,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#047857",
            hover_color="#065f46",
            command=self._open_result_file,
        )
        self.view_btn.pack(side="left", padx=(0, 8))

        self.reveal_btn = ctk.CTkButton(
            result_actions_row,
            text="📂 Show in Folder",
            width=120,
            height=28,
            font=ctk.CTkFont(size=11, weight="bold"),
            fg_color="#047857",
            hover_color="#065f46",
            command=self._reveal_in_folder,
        )
        self.reveal_btn.pack(side="left")

    def _on_mode_change(self, value):
        if "Encrypt" in value:
            self.execute_btn.configure(
                text="🔒  Encrypt File to .vault",
                fg_color=COLOR_ACCENT_ENCRYPT,
                hover_color="#0369a1",
            )
            self.mode_selector.configure(selected_color=COLOR_ACCENT_ENCRYPT)
            self.status_title_lbl.configure(text_color="#38bdf8")
        else:
            self.execute_btn.configure(
                text="🔓  Decrypt .vault File",
                fg_color=COLOR_ACCENT_DECRYPT,
                hover_color="#059669",
            )
            self.mode_selector.configure(selected_color=COLOR_ACCENT_DECRYPT)
            self.status_title_lbl.configure(text_color="#34d399")

        self._update_file_info()

    def _browse_file(self):
        is_encrypt = "Encrypt" in self.mode_selector.get()
        if is_encrypt:
            filename = filedialog.askopenfilename(title="Select File to Encrypt")
        else:
            filename = filedialog.askopenfilename(
                title="Select Encrypted File to Decrypt",
                filetypes=[("Vault Encrypted Files", "*.vault *.enc"), ("All Files", "*.*")],
            )

        if filename:
            self.selected_file_path.set(filename)
            self._update_file_info()

    def _update_file_info(self):
        path = self.selected_file_path.get().strip()
        if not path:
            self.file_info_lbl.configure(text="No file selected (O(1) streaming supports files of any size)")
            return

        if not os.path.exists(path):
            self.file_info_lbl.configure(text="⚠️ File does not exist on disk.", text_color="#f87171")
            return

        size = os.path.getsize(path)
        formatted_size = self._format_bytes(size)
        basename = os.path.basename(path)

        is_vault = path.endswith(".vault") or path.endswith(".enc")
        tag = " [Vault Archive]" if is_vault else ""
        self.file_info_lbl.configure(
            text=f"📄 {basename} • Size: {formatted_size}{tag}",
            text_color="#94a3b8",
        )

    def _toggle_password_visibility(self):
        self.is_password_visible = not self.is_password_visible
        if self.is_password_visible:
            self.pass_entry.configure(show="")
            self.show_pass_btn.configure(text="🔒")
        else:
            self.pass_entry.configure(show="•")
            self.show_pass_btn.configure(text="Show")

    def _generate_secure_password(self):
        # Generate 20-character high-entropy cryptographic password
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
        pwd = "".join(secrets.choice(alphabet) for _ in range(20))
        self.password_var.set(pwd)
        if not self.is_password_visible:
            self._toggle_password_visibility()

    def _on_password_change(self):
        pwd = self.password_var.get()
        if not pwd:
            self.strength_bar.set(0)
            self.strength_bar.configure(progress_color="#475569")
            self.strength_lbl.configure(text="Strength: None", text_color=COLOR_TEXT_MUTED)
            return

        score = 0
        if len(pwd) >= 8: score += 1
        if len(pwd) >= 14: score += 1
        if any(c.isupper() for c in pwd) and any(c.islower() for c in pwd): score += 1
        if any(c.isdigit() for c in pwd): score += 1
        if any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in pwd): score += 1

        if score <= 2:
            self.strength_bar.set(0.25)
            self.strength_bar.configure(progress_color="#ef4444")
            self.strength_lbl.configure(text="Strength: Weak", text_color="#ef4444")
        elif score == 3:
            self.strength_bar.set(0.55)
            self.strength_bar.configure(progress_color="#f59e0b")
            self.strength_lbl.configure(text="Strength: Moderate", text_color="#f59e0b")
        elif score == 4:
            self.strength_bar.set(0.8)
            self.strength_bar.configure(progress_color="#10b981")
            self.strength_lbl.configure(text="Strength: Strong", text_color="#10b981")
        else:
            self.strength_bar.set(1.0)
            self.strength_bar.configure(progress_color="#06b6d4")
            self.strength_lbl.configure(text="Strength: Military-Grade", text_color="#06b6d4")

    def _format_bytes(self, num_bytes: int) -> str:
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if num_bytes < 1024.0:
                return f"{num_bytes:.1f} {unit}"
            num_bytes /= 1024.0
        return f"{num_bytes:.1f} PB"

    def _start_processing(self):
        if self.is_processing:
            return

        file_path = self.selected_file_path.get().strip()
        password = self.password_var.get()
        mode = self.mode_selector.get()
        is_encrypt = "Encrypt" in mode

        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Invalid File", "Please select a valid existing file.")
            return

        if not password:
            messagebox.showerror("Missing Passphrase", "Please provide a passphrase for encryption/decryption.")
            return

        # Prepare UI for Background Execution
        self.is_processing = True
        self.execute_btn.configure(state="disabled", text=" Processing Vault Stream...")
        self.browse_btn.configure(state="disabled")
        self.mode_selector.configure(state="disabled")
        self.result_card.pack_forget()

        self.progress_bar.set(0)
        self.percent_lbl.configure(text="0%")
        self.status_title_lbl.configure(
            text=" Deriving 256-bit Key (PBKDF2 600K iterations)...",
            text_color="#f59e0b",
        )
        self.metrics_lbl.configure(text="Initializing cryptographic engine...")

        self.start_time = time.perf_counter()

        # Run crypto in non-blocking background thread
        thread = threading.Thread(
            target=self._worker_thread,
            args=(file_path, password, is_encrypt),
            daemon=True,
        )
        thread.start()

    def _worker_thread(self, file_path: str, password: str, is_encrypt: bool):
        try:
            total_size = os.path.getsize(file_path)
            desktop_dir = os.path.join(os.environ.get("OneDrive", ""), "Desktop")
            if not os.path.isdir(desktop_dir):
                desktop_dir = os.path.join(os.path.expanduser("~"), "Desktop")
            output_root = os.path.join(desktop_dir, "Secure Folder")

            if is_encrypt:
                output_dir = os.path.join(output_root, "Encrypted file")
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, os.path.basename(file_path) + ".vault")
            else:
                if file_path.endswith(".vault"):
                    output_name = os.path.basename(file_path[:-6])
                elif file_path.endswith(".enc"):
                    output_name = os.path.basename(file_path[:-4])
                else:
                    output_name = os.path.basename(file_path) + ".decrypted"

                output_dir = os.path.join(output_root, "Decrypted file")
                os.makedirs(output_dir, exist_ok=True)
                output_path = os.path.join(output_dir, output_name)
                if os.path.exists(output_path):
                    dir_name, base_name = os.path.split(output_path)
                    output_path = os.path.join(dir_name, f"restored_{base_name}")

            last_ui_update = 0.0
            def progress_callback(processed: int, total: int):
                nonlocal last_ui_update
                now = time.perf_counter()
                if processed >= total or (now - last_ui_update) >= 0.05:
                    last_ui_update = now
                    self.after(0, self._update_progress, processed, total)

            if is_encrypt:
                crypto_engine.encrypt_file(file_path, output_path, password, progress_callback=progress_callback)
            else:
                crypto_engine.decrypt_file(file_path, output_path, password, progress_callback=progress_callback)

            self.after(0, self._on_success, output_path, is_encrypt, total_size)

        except Exception as err:
            self.after(0, self._on_error, str(err), is_encrypt)

    def _update_progress(self, processed: int, total: int):
        fraction = processed / max(total, 1)
        self.progress_bar.set(fraction)
        self.percent_lbl.configure(text=f"{int(fraction * 100)}%")

        elapsed = max(time.perf_counter() - self.start_time, 0.001)
        speed = processed / elapsed

        speed_str = f"{self._format_bytes(speed)}/s"
        processed_str = self._format_bytes(processed)
        total_str = self._format_bytes(total)

        mode_str = "Encrypting" if "Encrypt" in self.mode_selector.get() else "Decrypting"
        self.status_title_lbl.configure(
            text=f" {mode_str} Stream ({speed_str})",
            text_color="#38bdf8",
        )
        self.metrics_lbl.configure(text=f"{processed_str} of {total_str} processed • Elapsed: {elapsed:.1f}s")

    def _on_success(self, output_path: str, is_encrypt: bool, total_size: int):
        self.is_processing = False
        self.last_output_path = output_path
        elapsed = time.perf_counter() - self.start_time

        self.progress_bar.set(1.0)
        self.percent_lbl.configure(text="100%")

        action_name = "Encrypted" if is_encrypt else "Decrypted"
        self.status_title_lbl.configure(
            text=f"✅ Vault Stream {action_name} Successfully",
            text_color="#34d399",
        )

        avg_speed = self._format_bytes(total_size / max(elapsed, 0.001))
        self.metrics_lbl.configure(
            text=f"Total: {self._format_bytes(total_size)} in {elapsed:.2f}s (Avg Speed: {avg_speed}/s)"
        )

        # Restore Controls
        self._on_mode_change(self.mode_selector.get())
        self.execute_btn.configure(state="normal")
        self.browse_btn.configure(state="normal")
        self.mode_selector.configure(state="normal")

        # Show Output Result Card
        self.result_lbl.configure(
            text=f" File {action_name} Successfully!",
            text_color="#a7f3d0",
        )
        self.result_path_lbl.configure(text=output_path)
        self.result_card.pack(fill="x", pady=(0, 15))

    def _on_error(self, err_msg: str, is_encrypt: bool):
        self.is_processing = False
        self.status_title_lbl.configure(
            text="❌ Operation Failed",
            text_color="#f87171",
        )
        self.metrics_lbl.configure(
            text=f"Operation failed: {err_msg}"
        )

        self._on_mode_change(self.mode_selector.get())
        self.execute_btn.configure(state="normal")
        self.browse_btn.configure(state="normal")
        self.mode_selector.configure(state="normal")

        messagebox.showerror(
            "Crypto Engine Failed",
            f"Unable to complete the operation:\n\n{err_msg}",
        )

    def _copy_result_path(self):
        if self.last_output_path:
            self.clipboard_clear()
            self.clipboard_append(self.last_output_path)
            messagebox.showinfo("Copied", "Output file path copied to clipboard!")

    def _reveal_in_folder(self):
        if self.last_output_path and os.path.exists(self.last_output_path):
            if sys.platform == "win32":
                subprocess.run(["explorer", "/select,", os.path.normpath(self.last_output_path)])
            elif sys.platform == "darwin":
                subprocess.run(["open", "-R", self.last_output_path])
            else:
                subprocess.run(["xdg-open", os.path.dirname(self.last_output_path)])

    def _open_result_file(self):
        if not self.last_output_path or not os.path.exists(self.last_output_path):
            messagebox.showwarning("File Not Found", "The encrypted or decrypted output file is not available.")
            return

        # Mitigate arbitrary code execution: do not auto-launch dangerous executables
        dangerous_exts = {".exe", ".bat", ".cmd", ".vbs", ".ps1", ".msi", ".scr", ".com", ".pif", ".jar", ".wsf"}
        _, ext = os.path.splitext(self.last_output_path.lower())
        if ext in dangerous_exts:
            messagebox.showinfo(
                "Security Safeguard",
                f"For your protection, executable files ({ext}) cannot be launched directly from Aegis Vault.\n\n"
                "The target folder has been opened in File Explorer instead."
            )
            self._open_output_folder()
            return

        try:
            if sys.platform == "win32":
                os.startfile(self.last_output_path)
            elif sys.platform == "darwin":
                subprocess.run(["open", self.last_output_path], check=False)
            else:
                subprocess.run(["xdg-open", self.last_output_path], check=False)
        except OSError as err:
            messagebox.showerror("Unable to Open File", str(err))

if __name__ == "__main__":
    if "--tk" in sys.argv or "--legacy" in sys.argv:
        if sys.platform == "win32":
            try:
                import ctypes
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("aegisvault.crypto.app.1.0")
            except Exception:
                pass

        try:
            app = ModernCryptoApp()
            app.mainloop()
        except KeyboardInterrupt:
            pass
    else:
        import launch_app
        launch_app.main()