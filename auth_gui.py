import tkinter as tk
from datetime import datetime
from tkinter import messagebox, scrolledtext, ttk

from auth_backend import AuthResult, login_user, register_user

TAG_COLORS = {
    "SYSTEM":   "#9cdcfe",
    "STEP":     "#c586c0",
    "SALT":     "#dcdcaa",
    "HASH":     "#dcdcaa",
    "RESULT":   "#4ec9b0",
    "SUCCESS":  "#6a9955",
    "ERROR":    "#f48771",
    "INFO":     "#d4d4d4",
    "MATCH":    "#6a9955",
    "MISMATCH": "#f48771",
}

CONSOLE_BG = "#1e1e1e"
HEADER_FG = "#d4d4d4"
DIVIDER = "─" * 78


class AuthDemoApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title("Cryptographic Authentication — Educational Demo")
        root.geometry("960x560")
        root.minsize(820, 460)

        self._build_header()
        self._build_body()

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg="#252526", padx=16, pady=12)
        header.pack(fill="x", side="top")
        tk.Label(
            header,
            text="Cryptographic Authentication — Educational Demo",
            font=("Segoe UI", 14, "bold"),
            fg="#ffffff",
            bg="#252526",
        ).pack(anchor="w")
        tk.Label(
            header,
            text="Salted SHA-256 hashing, visualized step-by-step.",
            font=("Segoe UI", 9),
            fg="#9cdcfe",
            bg="#252526",
        ).pack(anchor="w")

    def _build_body(self) -> None:
        body = tk.PanedWindow(
            self.root,
            orient=tk.HORIZONTAL,
            sashwidth=4,
            sashrelief="raised",
            bg="#3c3c3c",
        )
        body.pack(fill="both", expand=True)

        body.add(self._build_left_panel(body), minsize=320)
        body.add(self._build_right_panel(body), minsize=420)

    def _build_left_panel(self, parent: tk.Widget) -> tk.Frame:
        panel = tk.Frame(parent, padx=20, pady=20, bg="#f3f3f3")

        tk.Label(
            panel,
            text="User Action",
            font=("Segoe UI", 12, "bold"),
            bg="#f3f3f3",
            fg="#222",
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 12))

        tk.Label(panel, text="Username:", bg="#f3f3f3", font=("Segoe UI", 10)).grid(
            row=1, column=0, sticky="w", pady=6
        )
        self.username_entry = tk.Entry(panel, font=("Segoe UI", 10), width=26)
        self.username_entry.grid(row=1, column=1, sticky="ew", pady=6, padx=(8, 0))

        tk.Label(panel, text="Password:", bg="#f3f3f3", font=("Segoe UI", 10)).grid(
            row=2, column=0, sticky="w", pady=6
        )
        self.password_entry = tk.Entry(panel, font=("Segoe UI", 10), width=26, show="*")
        self.password_entry.grid(row=2, column=1, sticky="ew", pady=6, padx=(8, 0))

        btns = tk.Frame(panel, bg="#f3f3f3")
        btns.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(16, 0))
        btns.columnconfigure(0, weight=1)
        btns.columnconfigure(1, weight=1)

        ttk.Button(btns, text="Login", command=self.on_login).grid(
            row=0, column=0, sticky="ew", padx=(0, 4), ipady=4
        )
        ttk.Button(btns, text="Register", command=self.on_register).grid(
            row=0, column=1, sticky="ew", padx=(4, 0), ipady=4
        )

        tk.Label(
            panel,
            text="→ Watch the right panel to see what happens under the hood.",
            font=("Segoe UI", 9, "italic"),
            fg="#555",
            bg="#f3f3f3",
            wraplength=300,
            justify="left",
        ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(24, 0))

        panel.columnconfigure(1, weight=1)

        self.username_entry.focus_set()
        self.root.bind("<Return>", lambda _e: self.on_login())
        return panel

    def _build_right_panel(self, parent: tk.Widget) -> tk.Frame:
        panel = tk.Frame(parent, padx=12, pady=12, bg="#252526")

        tk.Label(
            panel,
            text="Live Hash Monitor",
            font=("Segoe UI", 12, "bold"),
            fg="#ffffff",
            bg="#252526",
        ).pack(anchor="w", pady=(0, 8))

        self.monitor = scrolledtext.ScrolledText(
            panel,
            wrap="word",
            font=("Consolas", 10),
            bg=CONSOLE_BG,
            fg=HEADER_FG,
            insertbackground=HEADER_FG,
            state="disabled",
            borderwidth=0,
            relief="flat",
            padx=10,
            pady=10,
        )
        self.monitor.pack(fill="both", expand=True)

        for tag, color in TAG_COLORS.items():
            self.monitor.tag_configure(tag, foreground=color)
        self.monitor.tag_configure("DIVIDER", foreground="#3c3c3c")
        self.monitor.tag_configure("HEADER", foreground="#ffffff", font=("Consolas", 10, "bold"))

        ttk.Button(panel, text="Clear Monitor", command=self.clear_monitor).pack(
            anchor="e", pady=(8, 0)
        )

        self._write_line("DIVIDER", DIVIDER)
        self._write_line("HEADER", "  Awaiting first authentication action...")
        self._write_line("DIVIDER", DIVIDER)
        return panel

    def _write_line(self, tag: str, text: str) -> None:
        self.monitor.configure(state="normal")
        self.monitor.insert("end", text + "\n", tag)
        self.monitor.configure(state="disabled")

    def _render_result(self, action: str, result: AuthResult) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.monitor.configure(state="normal")
        self.monitor.insert("end", "\n" + DIVIDER + "\n", "DIVIDER")
        self.monitor.insert("end", f"  [{timestamp}]  {action}\n", "HEADER")
        self.monitor.insert("end", DIVIDER + "\n", "DIVIDER")
        for tag, text in result.steps:
            self.monitor.insert("end", f"[{tag:<8}] {text}\n", tag)
        self.monitor.configure(state="disabled")
        self.monitor.see("end")

    def clear_monitor(self) -> None:
        self.monitor.configure(state="normal")
        self.monitor.delete("1.0", "end")
        self.monitor.configure(state="disabled")
        self._write_line("DIVIDER", DIVIDER)
        self._write_line("HEADER", "  Monitor cleared.")
        self._write_line("DIVIDER", DIVIDER)

    def _read_credentials(self) -> tuple[str, str]:
        username = self.username_entry.get()
        password = self.password_entry.get()
        self.password_entry.delete(0, tk.END)
        return username, password

    def on_login(self) -> None:
        username, password = self._read_credentials()
        result = login_user(username, password)
        self._render_result("LOGIN", result)
        if result.success:
            messagebox.showinfo("Login successful", result.message)
        else:
            messagebox.showerror("Login failed", result.message)

    def on_register(self) -> None:
        username, password = self._read_credentials()
        result = register_user(username, password)
        self._render_result("REGISTER", result)
        if result.success:
            messagebox.showinfo("Registration successful", result.message)
        else:
            messagebox.showerror("Registration failed", result.message)


if __name__ == "__main__":
    root = tk.Tk()
    AuthDemoApp(root)
    root.mainloop()
