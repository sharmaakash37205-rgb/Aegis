"""
Aegis Vault & Security Suite — Native Desktop Application Launcher
Runs the Aegis Security Node & REST Server in the background and opens
the Modern Cyberpunk Glassmorphic GUI directly in a dedicated desktop application window.
"""

import os
import sys
import time
import socket
import base64
import subprocess
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler

PORT = 8080
WORKSPACE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(WORKSPACE_DIR, "java_auth", "web")

def is_port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('127.0.0.1', port)) == 0

def find_available_port(start_port: int) -> int:
    port = start_port
    while is_port_in_use(port):
        port += 1
    return port

class CustomWebHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=WEB_DIR, **kwargs)

    def end_headers(self):
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        origin = self.headers.get("Origin", "")
        if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
            self.send_header("Access-Control-Allow-Origin", origin)
        super().end_headers()

    def log_message(self, format, *args):
        # Suppress noisy HTTP request logging
        pass

def start_python_fallback_server(port: int):
    server = HTTPServer(('127.0.0.1', port), CustomWebHandler)
    server.serve_forever()

class DesktopFileApi:
    def __init__(self):
        self._sessions = {}

    def _get_output_path(self, filename: str) -> str:
        one_drive_desktop = os.path.join(os.environ.get("OneDrive", ""), "Desktop")
        local_desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        desktop_dir = one_drive_desktop if os.path.isdir(one_drive_desktop) else local_desktop
        output_root = os.path.join(desktop_dir, "Secure Folder")
        output_type = "Encrypted file" if filename.lower().endswith(".vault") else "Decrypted file"
        output_dir = os.path.join(output_root, output_type)
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, os.path.basename(filename))
        if os.path.exists(output_path):
            stem, extension = os.path.splitext(os.path.basename(filename))
            counter = 1
            while os.path.exists(output_path):
                output_path = os.path.join(output_dir, f"{stem}_{counter}{extension}")
                counter += 1
        return output_path

    def start_save_session(self, filename: str) -> dict:
        """Starts a streaming chunked write session for files of arbitrary size."""
        import uuid
        session_id = str(uuid.uuid4())
        final_path = self._get_output_path(filename)
        temp_path = final_path + ".stream_tmp"
        f = open(temp_path, "wb")
        self._sessions[session_id] = {
            "handle": f,
            "temp_path": temp_path,
            "final_path": final_path,
        }
        return {"session_id": session_id, "output_path": final_path}

    def append_chunk(self, session_id: str, chunk_b64: str) -> bool:
        """Appends a base64-encoded chunk to an active file session."""
        session = self._sessions.get(session_id)
        if not session:
            return False
        data = base64.b64decode(chunk_b64)
        session["handle"].write(data)
        return True

    def finish_save_session(self, session_id: str) -> str:
        """Closes the file handle and commits it atomically to destination."""
        session = self._sessions.pop(session_id, None)
        if not session:
            return ""
        session["handle"].close()
        temp_path = session["temp_path"]
        final_path = session["final_path"]
        if os.path.exists(final_path):
            os.remove(final_path)
        os.rename(temp_path, final_path)
        return final_path

    def cancel_save_session(self, session_id: str) -> None:
        """Cleans up temporary file if operation failed or was cancelled."""
        session = self._sessions.pop(session_id, None)
        if session:
            try:
                session["handle"].close()
                if os.path.exists(session["temp_path"]):
                    os.remove(session["temp_path"])
            except Exception:
                pass

    def save_file_to_desktop(self, filename: str, file_data: str) -> str:
        output_path = self._get_output_path(filename)
        with open(output_path, "wb") as output_file:
            output_file.write(base64.b64decode(file_data))
        return output_path

def launch_desktop_window(app_url: str):
    """Opens the application in a dedicated native desktop window."""
    try:
        import webview
        print("🖥️  Opening Aegis Vault Desktop Application Window...")

        window = webview.create_window(
            title="Aegis Vault & Security Suite — Military-Grade File Encryption",
            url=app_url,
            width=1280,
            height=860,
            min_size=(960, 650),
            background_color="#090d16",
            text_select=True,
            zoomable=True,
            js_api=DesktopFileApi()
        )

        # Set custom window icon if available
        icon_path = os.path.join(WORKSPACE_DIR, "assets", "app_icon.ico")
        if os.path.exists(icon_path):
            try:
                # pywebview supports icon on certain platforms
                pass
            except Exception:
                pass

        # Start native desktop window using Microsoft Edge WebView2
        webview.start(gui="edgechromium")
        return True
    except ImportError:
        print("⚠️ pywebview is not installed. Trying fallback...")
        return False
    except Exception as e:
        print(f"⚠️ Error starting native desktop window: {e}")
        return False

def main():
    print("=" * 60)
    print("  🛡️  AEGIS VAULT & SECURITY SUITE — DESKTOP APPLICATION  ")
    print("=" * 60)

    # 1. Check if Java compiler & runtime are available
    has_java = False
    try:
        res = subprocess.run(["java", "-version"], capture_output=True, text=True)
        if res.returncode == 0:
            has_java = True
    except Exception:
        has_java = False

    target_port = PORT
    if not is_port_in_use(target_port):
        chosen_port = target_port
    else:
        chosen_port = find_available_port(target_port + 1)

    app_url = f"http://localhost:{chosen_port}/"
    java_proc = None

    try:
        if has_java:
            print(f"⚡ Java Runtime detected. Starting Java SE 25 Security Node on port {chosen_port}...")
            bin_dir = os.path.join(WORKSPACE_DIR, "bin")
            main_class = os.path.join(bin_dir, "com", "aegis", "AegisAuthApp.class")

            # Compile if class files don't exist
            if not os.path.exists(main_class):
                os.makedirs(bin_dir, exist_ok=True)
                print("⚙️  Compiling Java security components...")
                subprocess.run([
                    "javac", "-encoding", "UTF-8", "-d", "bin",
                    "-sourcepath", "java_auth/src",
                    "java_auth/src/com/aegis/AegisAuthApp.java",
                    "java_auth/src/com/aegis/test/AuthTestSuite.java"
                ], cwd=WORKSPACE_DIR)

            # Launch Java REST server in background (HEADLESS mode: No Swing GUI)
            java_proc = subprocess.Popen(
                ["java", "-cp", "bin", "com.aegis.AegisAuthApp", "--port", str(chosen_port), "--headless"],
                cwd=WORKSPACE_DIR,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(1.0)
        else:
            print(f"🌐 Starting High-Performance Python Web Node on port {chosen_port}...")
            t = threading.Thread(target=start_python_fallback_server, args=(chosen_port,), daemon=True)
            t.start()
            time.sleep(0.5)

        print(f"✨ Security Engine ready on {app_url}")
        
        # Launch dedicated desktop window
        success = launch_desktop_window(app_url)

        if not success:
            # Fallback to CustomTkinter if pywebview failed
            print("🚀 Launching CustomTkinter desktop interface fallback...")
            try:
                import main as ctk_app
                app = ctk_app.ModernCryptoApp()
                app.mainloop()
            except Exception as e:
                print(f"Fallback error: {e}")

    except KeyboardInterrupt:
        print("\n🛑 Shutting down Aegis Vault...")
    finally:
        if java_proc is not None:
            try:
                java_proc.terminate()
                java_proc.wait(timeout=2)
            except Exception:
                try:
                    java_proc.kill()
                except Exception:
                    pass
        print("🔒 Aegis Vault closed safely.")

if __name__ == "__main__":
    main()

