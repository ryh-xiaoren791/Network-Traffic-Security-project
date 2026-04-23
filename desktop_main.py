import tkinter as tk
import tkinter.font as tkfont
import webbrowser
import threading
import base64
import ipaddress
import re
from pathlib import Path
from tkinter import filedialog, ttk, messagebox

from src.app.runtime import AppRuntime
from src.config import CONFIG
from src.core.auth.service import AuthService


class DesktopApp:
    def __init__(self) -> None:
        self.runtime = AppRuntime()
        self.auth = AuthService(self.runtime.db)
        self.is_authenticated = False
        self.user_role = ""
        self.username = ""
        self.interfaces = []
        self._tree_hover_last: dict[str, str] = {}
        self._alert_anim_job: str | None = None
        self._alert_target_value = "0"
        self._offline_import_thread: threading.Thread | None = None
        self._offline_import_done = False
        self._offline_import_error = ""
        self._offline_import_result: tuple[int, int] = (0, 0)
        self._packet_query_thread: threading.Thread | None = None
        self._packet_query_done = False
        self._packet_query_error = ""
        self._packet_query_result: list[dict] = []
        self._packet_load_token = 0
        self._packet_render_job: str | None = None
        self._packet_render_chunk_size = 1200
        self._packet_virtual_threshold = 50000
        self._packet_virtual_enabled = False
        self._packet_virtual_window_size = 2400
        self._packet_virtual_window_start = 0
        self._packet_virtual_pending_start = 0
        self._packet_virtual_pending_keep_selected = True
        self._packet_virtual_render_job: str | None = None
        self._packet_tree_y_scroll: ttk.Scrollbar | None = None
        self._packet_detail_query_thread: threading.Thread | None = None
        self._packet_detail_query_token = 0
        self._packet_detail_cache: dict[int, dict] = {}
        self._packet_detail_cache_order: list[int] = []
        self._packet_detail_cache_max = 2000
        self._packet_time_base = 0.0
        self._current_packet_detail: dict | None = None
        self._packet_rows_in_view: list[dict] = []
        self._packet_tree_id_map: dict[str, int] = {}
        self._nav_collapsed = False
        self._nav_width_expanded = 190
        self.root = tk.Tk()
        self.root.title("网络流量安全监测与分析平台 个人版")
        self.root.geometry("1380x900")
        self.root.minsize(1220, 760)
        self.root.configure(background="#F5F7FA")

        self._init_style()
        self._build_login_view()
        self._build_main_view()
        self._show_login()
        self._tick()

    def _pick_font(self, candidates: list[str], size: int, weight: str = "normal") -> tuple[str, int, str]:
        available = set(tkfont.families(self.root))
        for name in candidates:
            if name in available:
                return (name, size, weight)
        return ("Consolas", size, weight)

    def _init_style(self) -> None:
        self.font_mono = self._pick_font(["Roboto Mono", "Consolas", "Courier New"], 10)
        self.font_mono_bold = self._pick_font(["Roboto Mono", "Consolas", "Courier New"], 10, "bold")
        self.font_title = self._pick_font(["Roboto Mono", "Consolas", "Courier New"], 18, "bold")
        
        style = ttk.Style(self.root)
        style.theme_use("clam")
        
        # The Blueprint Palette
        BG = "#F5F7FA"
        LINE = "#003366"
        REDLINE = "#FF3333"
        CYAN = "#0099CC"
        
        style.configure("TFrame", background=BG)
        style.configure("Top.TFrame", background=BG)
        style.configure("Top.TLabel", foreground=LINE, background=BG, font=self.font_mono_bold)
        style.configure("Path.TLabel", foreground=CYAN, background=BG, font=self.font_mono)
        style.configure("Title.TLabel", font=self.font_title, foreground=LINE, background=BG)
        style.configure("Muted.TLabel", foreground=CYAN, background=BG, font=self.font_mono)
        style.configure("Hint.TLabel", foreground=LINE, background=BG, font=self.font_mono)
        style.configure("Redline.TLabel", foreground=REDLINE, background=BG, font=self.font_mono)
        
        # Cards as technical boxes
        style.configure("Card.TLabelframe", background=BG, bordercolor=LINE, borderwidth=1, relief=tk.SOLID)
        style.configure("Card.TLabelframe.Label", background=BG, foreground=LINE, font=self.font_mono_bold, padding=(6, 0))
        
        style.configure("KpiCard.TFrame", background=BG, bordercolor=LINE, borderwidth=1, relief=tk.SOLID)
        style.configure("KpiTitle.TLabel", background=BG, foreground=CYAN, font=self.font_mono)
        style.configure("KpiValue.TLabel", background=BG, foreground=LINE, font=self._pick_font(["Roboto Mono", "Consolas"], 14, "bold"))
        style.configure("KpiAlertValue.TLabel", background=BG, foreground=LINE, font=self._pick_font(["Roboto Mono", "Consolas"], 20, "bold"))
        style.configure("KpiAlertDanger.TLabel", background=BG, foreground=REDLINE, font=self._pick_font(["Roboto Mono", "Consolas"], 20, "bold"))
        
        style.configure("EnvOk.TLabel", foreground=LINE, background=BG, font=self.font_mono_bold)
        style.configure("EnvWarn.TLabel", foreground=REDLINE, background=BG, font=self.font_mono_bold)
        
        # Stamp Buttons
        style.configure("Primary.TButton", font=self.font_mono_bold, foreground=LINE, background=BG, bordercolor=LINE, borderwidth=2, relief=tk.SOLID, padding=(12, 7))
        style.map("Primary.TButton", background=[("active", LINE), ("pressed", LINE)], foreground=[("active", BG), ("pressed", BG)])
        
        style.configure("Secondary.TButton", font=self.font_mono, foreground=LINE, background=BG, bordercolor=LINE, borderwidth=1, relief=tk.SOLID, padding=(10, 7))
        style.map("Secondary.TButton", background=[("active", LINE)], foreground=[("active", BG)])
        
        style.configure("Danger.TButton", font=self.font_mono, foreground=REDLINE, background=BG, bordercolor=REDLINE, borderwidth=2, relief=tk.SOLID, padding=(10, 7))
        style.map("Danger.TButton", background=[("active", REDLINE)], foreground=[("active", BG)])
        
        style.configure("TEntry", fieldbackground=BG, foreground=LINE, bordercolor=LINE, lightcolor=LINE, darkcolor=LINE, insertcolor=LINE, padding=(8, 6))
        style.map("TEntry", bordercolor=[("focus", CYAN)], lightcolor=[("focus", CYAN)], darkcolor=[("focus", CYAN)])
        
        style.configure("TCombobox", fieldbackground=BG, background=BG, foreground=LINE, bordercolor=LINE, arrowsize=14, padding=(6, 4))
        style.map("TCombobox", bordercolor=[("focus", CYAN), ("readonly", LINE)], lightcolor=[("focus", CYAN)], darkcolor=[("focus", CYAN)], fieldbackground=[("readonly", BG)])
        
        style.configure("TCheckbutton", background=BG, foreground=LINE, font=self.font_mono)
        style.map("TCheckbutton", indicatorbackground=[("selected", LINE), ("!selected", BG)], indicatorforeground=[("selected", BG)], background=[("active", BG)])
        
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG, foreground=CYAN, bordercolor=LINE, padding=(12, 8), font=self.font_mono)
        style.map("TNotebook.Tab", foreground=[("selected", LINE)], bordercolor=[("selected", LINE)], background=[("selected", BG), ("active", BG)])
        
        style.configure("Treeview", background=BG, fieldbackground=BG, foreground=LINE, bordercolor=LINE, rowheight=30, font=self.font_mono)
        style.configure("Treeview.Heading", background=BG, foreground=LINE, bordercolor=LINE, font=self.font_mono_bold, relief=tk.SOLID, borderwidth=1)
        style.map("Treeview", background=[("selected", "#E8ECEF")], foreground=[("selected", LINE)])
        style.map("Treeview.Heading", background=[("active", "#E8ECEF")])
        
        self.root.option_add("*TCombobox*Listbox.font", self.font_mono)
        self.root.option_add("*TCombobox*Listbox.background", BG)
        self.root.option_add("*TCombobox*Listbox.foreground", LINE)

    def _draw_grid(self, canvas: tk.Canvas, w: int, h: int):
        canvas.delete("grid")
        # 20px grid
        for i in range(0, w, 20):
            canvas.create_line(i, 0, i, h, fill="#E8ECEF", tags="grid")
        for i in range(0, h, 20):
            canvas.create_line(0, i, w, i, fill="#E8ECEF", tags="grid")
        # 100px major grid
        for i in range(0, w, 100):
            canvas.create_line(i, 0, i, h, fill="#D1D8E0", tags="grid")
        for i in range(0, h, 100):
            canvas.create_line(0, i, w, i, fill="#D1D8E0", tags="grid")

    def _build_login_view(self) -> None:
        self.login_frame = tk.Frame(self.root, bg="#F5F7FA")
        
        # Draw blueprint grid
        self.login_canvas = tk.Canvas(self.login_frame, bg="#F5F7FA", highlightthickness=0)
        self.login_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.login_canvas.bind("<Configure>", lambda e: self._draw_grid(self.login_canvas, e.width, e.height))

        box = ttk.LabelFrame(self.login_frame, text="[REF: AUTH_MODULE] 统一身份认证", style="Card.TLabelframe")
        box.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=560, height=420)
        
        ttk.Label(box, text="STRUCT: AI_TRAFFIC_MONITOR", style="Title.TLabel").pack(pady=(20, 12))

        self.login_user_var = tk.StringVar(value="admin")
        self.login_pass_var = tk.StringVar(value="Admin@123456")
        
        row1 = ttk.Frame(box)
        row1.pack(fill=tk.X, padx=28, pady=8)
        ttk.Label(row1, text="[ID] \u7528\u6237\u540d", width=16, style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(row1, textvariable=self.login_user_var).pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        row2 = ttk.Frame(box)
        row2.pack(fill=tk.X, padx=28, pady=8)
        ttk.Label(row2, text="[KEY] \u5bc6\u7801", width=16, style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(row2, textvariable=self.login_pass_var, show="*").pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        btns = ttk.Frame(box)
        btns.pack(fill=tk.X, padx=28, pady=16)
        ttk.Button(btns, text="[EXEC] 登录系统", style="Primary.TButton", command=self.login).pack(side=tk.LEFT, padx=4)
        
        tips = (
            "NOTES:\n"
            "  1. Default Admin: admin / Admin@123456\n"
            "  2. Default Guest: user / User@123456\n"
            "  3. Roles: admin=full access, guest=read only."
        )
        ttk.Label(box, text=tips, justify=tk.LEFT, style="Muted.TLabel").pack(padx=28, pady=8, anchor=tk.W)
        ttk.Label(box, text="* REDLINE: Authorized personnel only.", style="Redline.TLabel").pack(padx=28, anchor=tk.W)

    def _build_main_view(self) -> None:
        self.main_frame = tk.Frame(self.root, bg="#F5F7FA")
        
        self.main_canvas = tk.Canvas(self.main_frame, bg="#F5F7FA", highlightthickness=0)
        self.main_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.main_canvas.bind("<Configure>", lambda e: self._draw_grid(self.main_canvas, e.width, e.height))

        # Inner frame to hold content over canvas, allowing grid to show at borders
        content = tk.Frame(self.main_frame, bg="#F5F7FA")
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)

        top = ttk.Frame(content, style="Top.TFrame")
        top.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(top, text="[APP] AI流量异常检测系统 工作台", style="Top.TLabel").pack(side=tk.LEFT, padx=(0, 12), pady=8)
        ttk.Label(top, text="LOC: C:\\ProgramData\\AI-Traffic\\console", style="Path.TLabel").pack(side=tk.LEFT, pady=8)
        self.nav_toggle_btn = ttk.Button(top, text="[NAV] 收起侧栏", style="Secondary.TButton", command=self._toggle_nav_panel)
        self.nav_toggle_btn.pack(side=tk.LEFT, padx=8, pady=4)
        
        self.top_status_var = tk.StringVar(value="[STATUS: UNAUTH]")
        ttk.Label(top, textvariable=self.top_status_var, style="Top.TLabel").pack(side=tk.RIGHT, padx=12)
        ttk.Button(top, text="[EXIT] 退出登录", style="Danger.TButton", command=self.logout).pack(side=tk.RIGHT, padx=8, pady=4)
        body = ttk.Frame(content, style="TFrame")
        body.pack(fill=tk.BOTH, expand=True, pady=6)
        self.main_body_pane = tk.PanedWindow(body, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        self.main_body_pane.pack(fill=tk.BOTH, expand=True)

        self.nav_panel = ttk.LabelFrame(self.main_body_pane, text="[NAV] 模块路由", style="Card.TLabelframe", width=self._nav_width_expanded)
        self.nav_panel.pack_propagate(False)

        self.page_container = ttk.Frame(self.main_body_pane, style="TFrame")
        self.main_body_pane.add(self.nav_panel, minsize=150, width=self._nav_width_expanded)
        self.main_body_pane.add(self.page_container, minsize=860)

        self.route_buttons: dict[str, ttk.Button] = {}
        self.pages: dict[str, ttk.Frame] = {
            "traffic": ttk.Frame(self.page_container),
            "realtime": ttk.Frame(self.page_container),
            "lists": ttk.Frame(self.page_container),
            "logs": ttk.Frame(self.page_container),
        }

        routes = [
            ("traffic", "[PAGE] 流量分析"),
            ("realtime", "[PAGE] 实时监测"),
            ("lists", "[PAGE] 黑白名单管理"),
            ("logs", "[PAGE] 审计日志"),
        ]
        for route_key, title in routes:
            btn = ttk.Button(self.nav_panel, text=title, style="Secondary.TButton", command=lambda r=route_key: self._route_to(r))
            btn.pack(fill=tk.X, padx=10, pady=6)
            self.route_buttons[route_key] = btn

        self.page_traffic = self.pages["traffic"]
        self.page_realtime = self.pages["realtime"]
        self.page_lists = self.pages["lists"]
        self.page_logs = self.pages["logs"]
        self._build_traffic_tab()
        self._build_realtime_tab()
        self._build_lists_tab()
        self._build_logs_tab()
        self.current_route = "realtime"
        self._route_to("realtime")

    def _route_to(self, route: str) -> None:
        if route not in self.pages:
            return
        for key, frame in self.pages.items():
            if key == route:
                frame.pack(fill=tk.BOTH, expand=True)
            else:
                frame.pack_forget()
        for key, btn in self.route_buttons.items():
            btn.configure(style="Primary.TButton" if key == route else "Secondary.TButton")
        self.current_route = route
        if not self.is_authenticated:
            return
        if route == "traffic":
            self.load_packets()
        elif route == "realtime":
            self.load_alerts()
        elif route == "lists":
            self.load_list_items()
        elif route == "logs":
            self.load_logs()

    def _show_login(self) -> None:
        self.main_frame.pack_forget()
        self.login_frame.pack(fill=tk.BOTH, expand=True)
        self.root.attributes("-alpha", 1.0)

    def _show_main(self) -> None:
        self.login_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.root.after(80, self._apply_default_layout)

    def _pane_contains(self, pane: tk.PanedWindow, widget: tk.Widget) -> bool:
        try:
            return str(widget) in pane.panes()
        except tk.TclError:
            return False

    def _toggle_nav_panel(self) -> None:
        if self._nav_collapsed:
            if self._pane_contains(self.main_body_pane, self.page_container):
                self.main_body_pane.forget(self.page_container)
            self.main_body_pane.add(self.nav_panel, minsize=150, width=self._nav_width_expanded)
            self.main_body_pane.add(self.page_container, minsize=860)
            self._nav_collapsed = False
            self.nav_toggle_btn.configure(text="[NAV] 收起侧栏")
            self.root.after(20, self._apply_default_layout)
            return
        if self._pane_contains(self.main_body_pane, self.nav_panel):
            self.main_body_pane.forget(self.nav_panel)
        self._nav_collapsed = True
        self.nav_toggle_btn.configure(text="[NAV] 展开侧栏")

    def _apply_default_layout(self) -> None:
        self.root.update_idletasks()
        try:
            if len(self.main_body_pane.panes()) > 1 and not self._nav_collapsed:
                self.main_body_pane.sash_place(0, self._nav_width_expanded, 0)
        except tk.TclError:
            pass
        try:
            if len(self.traffic_split.panes()) > 1:
                height = max(0, int(self.traffic_split.winfo_height()))
                if height > 240:
                    self.traffic_split.sash_place(0, 0, int(height * 0.64))
        except (AttributeError, tk.TclError):
            pass
        try:
            if len(self.realtime_split.panes()) > 1:
                height = max(0, int(self.realtime_split.winfo_height()))
                if height > 240:
                    self.realtime_split.sash_place(0, 0, int(height * 0.68))
        except (AttributeError, tk.TclError):
            pass

    def _animate_transition(self, on_complete) -> None:
        self._fade_out(1.0, on_complete)

    def _fade_out(self, alpha: float, on_complete) -> None:
        if alpha <= 0.0:
            on_complete()
            self._fade_in(0.0)
        else:
            self.root.attributes("-alpha", alpha)
            self.root.after(15, self._fade_out, alpha - 0.1, on_complete)

    def _fade_in(self, alpha: float) -> None:
        if alpha >= 1.0:
            self.root.attributes("-alpha", 1.0)
        else:
            self.root.attributes("-alpha", alpha)
            self.root.after(15, self._fade_in, alpha + 0.1)

    def _build_traffic_tab(self) -> None:
        bar = ttk.Frame(self.page_traffic)
        bar.pack(fill=tk.X, pady=6)
        bar1 = ttk.Frame(bar)
        bar1.pack(fill=tk.X, pady=(0, 4), anchor=tk.W)
        bar2 = ttk.Frame(bar)
        bar2.pack(fill=tk.X, anchor=tk.W)
        self.packet_filter_process_var = tk.StringVar()
        self.packet_filter_ip_var = tk.StringVar()
        self.packet_filter_source_var = tk.StringVar(value="")
        self.packet_rule_expr_var = tk.StringVar()
        self.packet_only_abnormal_var = tk.BooleanVar(value=False)
        self.offline_mode_var = tk.StringVar(value="balanced")
        self.packet_import_status_var = tk.StringVar(value="离线分析状态: 空闲")
        self.packet_sort_key_var = tk.StringVar(value="ts")
        self.packet_sort_desc_var = tk.BooleanVar(value=True)
        ttk.Label(bar1, text="[PROC]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(bar1, textvariable=self.packet_filter_process_var, width=16).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Label(bar1, text="[IP]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(bar1, textvariable=self.packet_filter_ip_var, width=16).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Label(bar1, text="[SRC]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Combobox(bar1, textvariable=self.packet_filter_source_var, values=["", "live", "offline"], width=10, state="readonly").pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(bar1, text="[ABN] 仅异常关联", variable=self.packet_only_abnormal_var).pack(side=tk.LEFT, padx=4)
        ttk.Label(bar1, text="[RULE]:", style="Hint.TLabel").pack(side=tk.LEFT, padx=(8, 0))
        ttk.Entry(bar1, textvariable=self.packet_rule_expr_var, width=30).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Label(bar2, text="[SORT]:", style="Hint.TLabel").pack(side=tk.LEFT, padx=(0, 0))
        ttk.Combobox(
            bar2,
            textvariable=self.packet_sort_key_var,
            values=["ts", "id", "risk_level", "process_name", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length", "source"],
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[ORDER] 升降切换", style="Secondary.TButton", command=self._toggle_packet_sort_order).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[CMD] 查询流量", style="Secondary.TButton", command=self.load_packets).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[RESET] 重置显示窗口", style="Danger.TButton", command=self.reset_traffic_display).pack(side=tk.LEFT, padx=4)
        ttk.Label(bar2, text="[MODE]:", style="Hint.TLabel").pack(side=tk.LEFT, padx=(6, 0))
        ttk.Combobox(
            bar2,
            textvariable=self.offline_mode_var,
            values=["balanced", "extreme"],
            width=12,
            state="readonly",
        ).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[FILE] 导入离线PCAP", style="Secondary.TButton", command=self.import_offline_pcap).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[VIEW] 原始包窗口", style="Secondary.TButton", command=self.open_packet_raw_viewer).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[FLOW] 跟踪会话", style="Secondary.TButton", command=self.open_follow_stream_viewer).pack(side=tk.LEFT, padx=4)
        ttk.Label(
            self.page_traffic,
            text="规则示例: tcp && ip.src==10.0.0.2  |  udp && port==53  |  process contains chrome  |  !icmp && len>100",
            style="Hint.TLabel",
        ).pack(fill=tk.X, pady=(0, 4), anchor=tk.W)
        ttk.Label(self.page_traffic, textvariable=self.packet_import_status_var, style="Redline.TLabel").pack(fill=tk.X, pady=(0, 6), anchor=tk.W)
        self.packet_progress_var = tk.DoubleVar(value=0.0)
        self.packet_progress = ttk.Progressbar(self.page_traffic, maximum=100.0, variable=self.packet_progress_var)
        self.packet_progress.pack(fill=tk.X, pady=(0, 6))
        self.traffic_split = tk.PanedWindow(self.page_traffic, orient=tk.VERTICAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        self.traffic_split.pack(fill=tk.BOTH, expand=True, pady=(0, 6))
        packet_table = ttk.Frame(self.traffic_split)
        cols = ("no", "delta", "ts", "source", "risk_level", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "length", "info")
        self.packet_tree = ttk.Treeview(packet_table, columns=cols, show="headings", height=23)
        for c, w in [
            ("no", 70),
            ("delta", 90),
            ("ts", 150),
            ("source", 80),
            ("risk_level", 90),
            ("src_ip", 130),
            ("src_port", 85),
            ("dst_ip", 130),
            ("dst_port", 85),
            ("proto", 90),
            ("length", 90),
            ("info", 520),
        ]:
            self.packet_tree.heading(c, text=f"[{c.upper()}]", command=lambda col=c: self._on_packet_heading_sort(col))
            self.packet_tree.column(c, width=w, anchor=tk.W)
        packet_table.columnconfigure(0, weight=1)
        packet_table.rowconfigure(0, weight=1)
        self.packet_tree_y_scroll = ttk.Scrollbar(packet_table, orient=tk.VERTICAL, command=self._on_packet_tree_yview)
        packet_tree_x_scroll = ttk.Scrollbar(packet_table, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
        self.packet_tree.configure(yscrollcommand=self._on_packet_tree_yscroll, xscrollcommand=packet_tree_x_scroll.set)
        self.packet_tree.grid(row=0, column=0, sticky="nsew")
        self.packet_tree_y_scroll.grid(row=0, column=1, sticky="ns")
        packet_tree_x_scroll.grid(row=1, column=0, sticky="ew")
        self.packet_tree.bind("<Double-1>", self._on_packet_double_click)
        self.packet_tree.bind("<<TreeviewSelect>>", self._on_packet_select)
        self.packet_tree.bind("<MouseWheel>", self._on_packet_tree_mousewheel)
        self.packet_tree.bind("<Button-4>", self._on_packet_tree_mousewheel)
        self.packet_tree.bind("<Button-5>", self._on_packet_tree_mousewheel)
        self._setup_tree(self.packet_tree)
        detail_frame = ttk.LabelFrame(self.traffic_split, text="[DETAIL] 协议分层与原始字节", style="Card.TLabelframe")
        detail_frame.rowconfigure(0, weight=1)
        detail_frame.columnconfigure(0, weight=1)
        self.traffic_split.add(packet_table, minsize=260)
        self.traffic_split.add(detail_frame, minsize=180)
        paned = tk.PanedWindow(detail_frame, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        paned.grid(row=0, column=0, sticky="nsew")

        left = ttk.Frame(paned)
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)
        self.packet_detail_tree = ttk.Treeview(left, columns=("value",), show="tree headings", height=10)
        self.packet_detail_tree.heading("#0", text="[FIELD]")
        self.packet_detail_tree.heading("value", text="[VALUE]")
        self.packet_detail_tree.column("#0", width=260, anchor=tk.W)
        self.packet_detail_tree.column("value", width=380, anchor=tk.W)
        self._attach_tree_scrollbars(left, self.packet_detail_tree)
        self._setup_tree(self.packet_detail_tree)
        paned.add(left, minsize=420)

        right = ttk.Frame(paned)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(2, weight=1)
        self.packet_raw_mode_var = tk.StringVar(value="hex")
        raw_bar = ttk.Frame(right)
        raw_bar.grid(row=0, column=0, sticky="ew", padx=4, pady=(4, 2))
        ttk.Label(raw_bar, text="[RAW] 编码", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Combobox(raw_bar, textvariable=self.packet_raw_mode_var, values=["hex", "ascii", "utf-8", "base64"], width=12, state="readonly").pack(side=tk.LEFT, padx=4)
        self.packet_expert_text = tk.Text(
            right,
            height=5,
            bg="#F5F7FA",
            fg="#003366",
            insertbackground="#003366",
            relief=tk.SOLID,
            borderwidth=1,
            font=self.font_mono,
            wrap=tk.WORD,
        )
        self.packet_expert_text.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
        self.packet_expert_text.insert("1.0", "Expert Info:\n- 选择一条流量记录后显示分析结论。")
        self.packet_expert_text.configure(state=tk.DISABLED)
        self.packet_detail_text = tk.Text(
            right,
            height=10,
            bg="#F5F7FA",
            fg="#003366",
            insertbackground="#003366",
            relief=tk.SOLID,
            borderwidth=1,
            font=self.font_mono,
            wrap=tk.NONE,
        )
        self.packet_detail_text.grid(row=2, column=0, sticky="nsew", padx=4, pady=(0, 4))
        raw_y_scroll = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.packet_detail_text.yview)
        raw_y_scroll.grid(row=2, column=1, sticky="ns", pady=(0, 4))
        self.packet_detail_text.configure(yscrollcommand=raw_y_scroll.set)
        self.packet_detail_text.insert("1.0", "选择一条流量记录可查看分层详情与原始字节。")
        self.packet_detail_text.configure(state=tk.DISABLED)
        self.packet_raw_mode_var.trace_add("write", lambda *_: self._render_current_packet_raw())
        paned.add(right, minsize=460)

    def _build_realtime_tab(self) -> None:
        env_box = ttk.LabelFrame(self.page_realtime, text="[BLK-1] 系统状态头", style="Card.TLabelframe")
        env_box.pack(fill=tk.X, pady=6)
        self.env_var = tk.StringVar(value="正在识别环境...")
        self.env_label = ttk.Label(env_box, textvariable=self.env_var, justify=tk.LEFT, style="EnvOk.TLabel")
        self.env_label.pack(anchor=tk.W, padx=12, pady=8)

        toolbar = ttk.LabelFrame(self.page_realtime, text="[BLK-2] 监控控制区", style="Card.TLabelframe")
        toolbar.pack(fill=tk.X, pady=6)
        self.iface_var = tk.StringVar()
        self.iface_box = ttk.Combobox(toolbar, textvariable=self.iface_var, width=42, state="readonly")
        self.iface_box.grid(row=0, column=0, padx=8, pady=8, sticky="w")
        self.mode_var = tk.StringVar(value="fast")
        self.mode_box = ttk.Combobox(toolbar, textvariable=self.mode_var, values=["fast", "standard"], width=12, state="readonly")
        self.mode_box.grid(row=0, column=1, padx=8, pady=8, sticky="w")
        self.outbound_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(toolbar, text="[OPT] 开启出站抓取", variable=self.outbound_var).grid(row=0, column=2, padx=8, pady=8, sticky="w")
        ttk.Button(toolbar, text="[RUN] 开始采集", style="Primary.TButton", command=self.start_capture).grid(row=0, column=3, padx=6, pady=8)
        ttk.Button(toolbar, text="[HALT] 停止采集", style="Danger.TButton", command=self.stop_capture).grid(row=0, column=4, padx=6, pady=8)
        ttk.Button(toolbar, text="[SYNC] 刷新网卡", style="Secondary.TButton", command=self._refresh_interfaces).grid(row=1, column=0, padx=8, pady=(0, 8), sticky="w")
        ttk.Button(toolbar, text="[NIC+] 启用网卡", style="Secondary.TButton", command=self.enable_interface).grid(row=1, column=1, padx=8, pady=(0, 8), sticky="w")
        ttk.Button(toolbar, text="[NIC-] 停用网卡", style="Danger.TButton", command=self.disable_interface).grid(row=1, column=2, padx=8, pady=(0, 8), sticky="w")
        ttk.Button(toolbar, text="[RPT] 生成分析报告", style="Secondary.TButton", command=self.generate_security_report).grid(row=1, column=3, padx=8, pady=(0, 8), sticky="w")
        self.mode_tips_var = tk.StringVar(value="* NOTE: fast=30s; standard=3m; no alerts during learning phase.")
        ttk.Label(toolbar, textvariable=self.mode_tips_var, style="Redline.TLabel").grid(row=2, column=0, columnspan=9, padx=8, pady=4, sticky="w")
        self.learning_var = tk.StringVar(value="STATUS: IDLE")
        ttk.Label(toolbar, textvariable=self.learning_var, style="Hint.TLabel").grid(row=3, column=0, columnspan=9, padx=8, pady=4, sticky="w")

        kpi = ttk.LabelFrame(self.page_realtime, text="[BLK-3] 态势数据看板", style="Card.TLabelframe")
        kpi.pack(fill=tk.X, pady=6)
        for i in range(5):
            kpi.columnconfigure(i, weight=1, uniform="kpi")
        self.kpi_total = tk.StringVar(value="0")
        self.kpi_alerts = tk.StringVar(value="0")
        self.kpi_uptime = tk.StringVar(value="0")
        self.kpi_sessions = tk.StringVar(value="0")
        self.kpi_privacy_blocks = tk.StringVar(value="0")
        card_total = ttk.Frame(kpi, style="KpiCard.TFrame", padding=(12, 10))
        card_total.grid(row=0, column=0, padx=8, pady=8, sticky="nsew")
        ttk.Label(card_total, text="[MEASURE] 总流量包数", style="KpiTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(card_total, textvariable=self.kpi_total, style="KpiValue.TLabel").pack(anchor=tk.W, pady=(6, 0))
        card_alert = ttk.Frame(kpi, style="KpiCard.TFrame", padding=(12, 10))
        card_alert.grid(row=0, column=1, padx=8, pady=8, sticky="nsew")
        ttk.Label(card_alert, text="[MEASURE] 当前告警数", style="KpiTitle.TLabel").pack(anchor=tk.W)
        self.kpi_alert_value_label = ttk.Label(card_alert, textvariable=self.kpi_alerts, style="KpiAlertValue.TLabel")
        self.kpi_alert_value_label.pack(anchor=tk.W, pady=(4, 0))
        card_uptime = ttk.Frame(kpi, style="KpiCard.TFrame", padding=(12, 10))
        card_uptime.grid(row=0, column=2, padx=8, pady=8, sticky="nsew")
        ttk.Label(card_uptime, text="[MEASURE] 在线时长", style="KpiTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(card_uptime, textvariable=self.kpi_uptime, style="KpiValue.TLabel").pack(anchor=tk.W, pady=(6, 0))
        card_session = ttk.Frame(kpi, style="KpiCard.TFrame", padding=(12, 10))
        card_session.grid(row=0, column=3, padx=8, pady=8, sticky="nsew")
        ttk.Label(card_session, text="[MEASURE] 活动会话", style="KpiTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(card_session, textvariable=self.kpi_sessions, style="KpiValue.TLabel").pack(anchor=tk.W, pady=(6, 0))
        card_privacy = ttk.Frame(kpi, style="KpiCard.TFrame", padding=(12, 10))
        card_privacy.grid(row=0, column=4, padx=8, pady=8, sticky="nsew")
        ttk.Label(card_privacy, text="[MEASURE] 隐私追踪拦截", style="KpiTitle.TLabel").pack(anchor=tk.W)
        ttk.Label(card_privacy, textvariable=self.kpi_privacy_blocks, style="KpiValue.TLabel").pack(anchor=tk.W, pady=(6, 0))
        bar = ttk.Frame(self.page_realtime)
        bar.pack(fill=tk.X, pady=6)
        self.filter_process_var = tk.StringVar()
        self.filter_ip_var = tk.StringVar()
        self.filter_level_var = tk.StringVar(value="")
        ttk.Label(bar, text="[PROC]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(bar, textvariable=self.filter_process_var, width=18).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Label(bar, text="[IP]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(bar, textvariable=self.filter_ip_var, width=18).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Label(bar, text="[LVL]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Combobox(bar, textvariable=self.filter_level_var, values=["", "high", "medium", "low"], width=12, state="readonly").pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="[CMD] 查询告警", style="Secondary.TButton", command=self.load_alerts).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="[RESET] 重置显示窗口", style="Danger.TButton", command=self.reset_realtime_display).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="[BLOCK] 一键封禁源IP", style="Danger.TButton", command=self.block_selected_alert_ip).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar, text="[VIEW] 告警详情弹窗", style="Secondary.TButton", command=self.open_alert_detail_window).pack(side=tk.LEFT, padx=4)
        self.realtime_split = tk.PanedWindow(self.page_realtime, orient=tk.VERTICAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        self.realtime_split.pack(fill=tk.BOTH, expand=True)
        alert_table = ttk.Frame(self.realtime_split)
        cols = ("ts", "src_ip", "dst_ip", "process_name", "level", "attack_type", "sub_category", "reason")
        self.alert_tree = ttk.Treeview(alert_table, columns=cols, show="headings", height=23)
        for c, w in [("ts", 150), ("src_ip", 120), ("dst_ip", 120), ("process_name", 130), ("level", 70), ("attack_type", 130), ("sub_category", 140), ("reason", 430)]:
            self.alert_tree.heading(c, text=f"[{c.upper()}]")
            self.alert_tree.column(c, width=w, anchor=tk.W)
        self._attach_tree_scrollbars(alert_table, self.alert_tree)
        self.alert_tree.bind("<<TreeviewSelect>>", self._on_alert_select)
        self._setup_tree(self.alert_tree)
        panel = ttk.Frame(self.realtime_split)
        self.realtime_split.add(alert_table, minsize=260)
        self.realtime_split.add(panel, minsize=170)
        self.attack_desc_text = tk.Text(
            panel,
            height=8,
            bg="#F5F7FA",
            fg="#003366",
            insertbackground="#003366",
            relief=tk.SOLID,
            borderwidth=1,
            font=self.font_mono,
            wrap=tk.WORD,
        )
        self.attack_desc_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 6))
        self.attack_desc_text.insert("1.0", "选择告警可查看攻击类型说明与处置建议。")
        self.attack_desc_text.configure(state=tk.DISABLED)
        self.attack_stats_text = tk.Text(
            panel,
            width=42,
            height=8,
            bg="#F5F7FA",
            fg="#003366",
            insertbackground="#003366",
            relief=tk.SOLID,
            borderwidth=1,
            font=self.font_mono,
            wrap=tk.WORD,
        )
        self.attack_stats_text.pack(side=tk.RIGHT, fill=tk.Y)
        self.attack_stats_text.insert("1.0", "攻击统计将在加载告警后显示。")
        self.attack_stats_text.configure(state=tk.DISABLED)

    def open_alert_detail_window(self) -> None:
        desc = self.attack_desc_text.get("1.0", tk.END).strip() if hasattr(self, "attack_desc_text") else ""
        stats = self.attack_stats_text.get("1.0", tk.END).strip() if hasattr(self, "attack_stats_text") else ""
        if not desc:
            desc = "选择告警可查看攻击类型说明与处置建议。"
        if not stats:
            stats = "攻击统计将在加载告警后显示。"

        dlg = tk.Toplevel(self.root)
        dlg.title("告警详情")
        dlg.geometry("980x560")
        dlg.configure(bg="#F5F7FA")
        split = tk.PanedWindow(dlg, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        split.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = ttk.LabelFrame(split, text="[DETAIL] 攻击说明", style="Card.TLabelframe")
        right = ttk.LabelFrame(split, text="[STATS] 攻击统计", style="Card.TLabelframe")
        split.add(left, minsize=520)
        split.add(right, minsize=260)

        detail_text = tk.Text(
            left,
            bg="#F5F7FA",
            fg="#003366",
            insertbackground="#003366",
            relief=tk.SOLID,
            borderwidth=1,
            font=self.font_mono,
            wrap=tk.WORD,
        )
        detail_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        detail_text.insert("1.0", desc)
        detail_text.configure(state=tk.DISABLED)

        stats_text = tk.Text(
            right,
            bg="#F5F7FA",
            fg="#003366",
            insertbackground="#003366",
            relief=tk.SOLID,
            borderwidth=1,
            font=self.font_mono,
            wrap=tk.WORD,
        )
        stats_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        stats_text.insert("1.0", stats)
        stats_text.configure(state=tk.DISABLED)

    def _build_lists_tab(self) -> None:
        bar = ttk.Frame(self.page_lists)
        bar.pack(fill=tk.X, pady=6)
        bar1 = ttk.Frame(bar)
        bar1.pack(fill=tk.X, pady=(0, 4), anchor=tk.W)
        bar2 = ttk.Frame(bar)
        bar2.pack(fill=tk.X, anchor=tk.W)
        self.list_ip_var = tk.StringVar()
        self.list_type_var = tk.StringVar(value="white")
        self.list_remark_var = tk.StringVar()
        ttk.Label(bar1, text="[IP]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(bar1, textvariable=self.list_ip_var, width=20).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Label(bar1, text="[TYP]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Combobox(bar1, textvariable=self.list_type_var, values=["white", "black"], width=10, state="readonly").pack(side=tk.LEFT, padx=4)
        ttk.Label(bar1, text="[RMK]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(bar1, textvariable=self.list_remark_var, width=24).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Button(bar2, text="[CMD] 新增", style="Primary.TButton", command=self.add_list_item).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[CMD] 启停切换", style="Secondary.TButton", command=self.toggle_selected_list).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[CMD] 删除", style="Danger.TButton", command=self.delete_selected_list).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[CMD] 刷新", style="Secondary.TButton", command=self.load_list_items).pack(side=tk.LEFT, padx=4)
        cols = ("id", "ip", "list_type", "enabled", "remark", "updated_at")
        self.list_tree = ttk.Treeview(self.page_lists, columns=cols, show="headings", height=23)
        for c, w in [("id", 60), ("ip", 170), ("list_type", 90), ("enabled", 80), ("remark", 300), ("updated_at", 220)]:
            self.list_tree.heading(c, text=f"[{c.upper()}]")
            self.list_tree.column(c, width=w, anchor=tk.W)
        self.list_tree.pack(fill=tk.BOTH, expand=True)
        self._setup_tree(self.list_tree)

    def _build_logs_tab(self) -> None:
        bar = ttk.Frame(self.page_logs)
        bar.pack(fill=tk.X, pady=6)
        bar1 = ttk.Frame(bar)
        bar1.pack(fill=tk.X, pady=(0, 4), anchor=tk.W)
        bar2 = ttk.Frame(bar)
        bar2.pack(fill=tk.X, anchor=tk.W)
        self.log_keyword_var = tk.StringVar()
        ttk.Label(bar1, text="[KWD]:", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Entry(bar1, textvariable=self.log_keyword_var, width=24).pack(side=tk.LEFT, padx=4, pady=2)
        ttk.Button(bar2, text="[CMD] 查询", style="Secondary.TButton", command=self.load_logs).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[CMD] 删除选中", style="Danger.TButton", command=self.delete_selected_log).pack(side=tk.LEFT, padx=4)
        ttk.Button(bar2, text="[CMD] 按过滤批量删除", style="Danger.TButton", command=self.delete_filtered_logs).pack(side=tk.LEFT, padx=4)
        log_table = ttk.Frame(self.page_logs)
        log_table.pack(fill=tk.BOTH, expand=True)
        cols = ("id", "ts", "username", "action", "target", "detail")
        self.log_tree = ttk.Treeview(log_table, columns=cols, show="headings", height=23)
        for c, w in [("id", 60), ("ts", 150), ("username", 120), ("action", 170), ("target", 180), ("detail", 620)]:
            self.log_tree.heading(c, text=f"[{c.upper()}]")
            self.log_tree.column(c, width=w, anchor=tk.W)
        self._attach_tree_scrollbars(log_table, self.log_tree)
        self._setup_tree(self.log_tree)

    def _attach_tree_scrollbars(self, parent: tk.Widget, tree: ttk.Treeview) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        y_scroll = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        x_scroll = ttk.Scrollbar(parent, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

    def _setup_tree(self, tree: ttk.Treeview) -> None:
        tree.tag_configure("even", background="#F5F7FA")
        tree.tag_configure("odd", background="#F5F7FA")
        tree.tag_configure("hover", background="#E8ECEF")
        tree.tag_configure("lvl_high", foreground="#FF3333")
        tree.tag_configure("lvl_medium", foreground="#0099CC")
        tree.tag_configure("proto_http", foreground="#005A9C")
        tree.tag_configure("proto_dns", foreground="#6A1B9A")
        tree.tag_configure("proto_tls", foreground="#1B5E20")
        tree.bind("<Motion>", lambda e, t=tree: self._on_tree_motion(t, e))
        tree.bind("<Leave>", lambda e, t=tree: self._on_tree_leave(t))

    def _strip_hover_tag(self, tree: ttk.Treeview, item_id: str) -> None:
        tags = tuple(tag for tag in tree.item(item_id, "tags") if tag != "hover")
        tree.item(item_id, tags=tags)

    def _on_tree_motion(self, tree: ttk.Treeview, event: tk.Event) -> None:
        item_id = tree.identify_row(event.y)
        key = str(tree)
        prev = self._tree_hover_last.get(key, "")
        if prev and prev != item_id and tree.exists(prev):
            self._strip_hover_tag(tree, prev)
        if item_id and tree.exists(item_id):
            tags = tree.item(item_id, "tags")
            if "hover" not in tags:
                tree.item(item_id, tags=tuple(list(tags) + ["hover"]))
            self._tree_hover_last[key] = item_id

    def _on_tree_leave(self, tree: ttk.Treeview) -> None:
        key = str(tree)
        prev = self._tree_hover_last.get(key, "")
        if prev and tree.exists(prev):
            self._strip_hover_tag(tree, prev)
        self._tree_hover_last[key] = ""

    def login(self) -> None:
        user = self.auth.login(self.login_user_var.get().strip(), self.login_pass_var.get())
        if not user:
            messagebox.showerror("ERR_AUTH", "Invalid credentials.")
            return
        self.is_authenticated = True
        self.user_role = user.role
        self.username = user.username
        self.top_status_var.set(f"[STATUS: AUTH_OK] USER:{self.username} ROLE:{self.user_role}")
        self._refresh_interfaces()
        self._refresh_environment_summary()
        self._route_to("realtime")
        self._animate_transition(self._show_main)

    def logout(self) -> None:
        self.is_authenticated = False
        self.user_role = ""
        self.username = ""
        self._cancel_packet_render()
        self._packet_load_token += 1
        self.runtime.stop_capture()
        self._route_to("realtime")
        self._animate_transition(self._show_login)

    def _is_admin(self) -> bool:
        return self.user_role == "admin"

    def _require_admin(self) -> bool:
        if self._is_admin():
            return True
        messagebox.showwarning("ERR_PERM", "管理员权限 required.")
        return False

    def _toggle_packet_sort_order(self) -> None:
        self.packet_sort_desc_var.set(not self.packet_sort_desc_var.get())
        self.load_packets()

    def _on_packet_heading_sort(self, column: str) -> None:
        if self.packet_sort_key_var.get() == column:
            self.packet_sort_desc_var.set(not self.packet_sort_desc_var.get())
        else:
            self.packet_sort_key_var.set(column)
            self.packet_sort_desc_var.set(True)
        self.load_packets()

    def _packet_sort_value(self, row: dict, key: str):
        k = str(key or "").strip().lower()
        if k in {"id", "src_port", "dst_port", "length"}:
            return int(row.get(k, 0) or 0)
        if k == "risk_level":
            risk = str(row.get("risk_level", "normal")).lower()
            if risk == "high":
                return 3
            if risk == "medium":
                return 2
            if risk == "low":
                return 1
            return 0
        return str(row.get(k, "") or "").lower()

    def _parse_rule_term(self, term: str) -> tuple[str, str, str] | None:
        m = re.match(r"^([a-zA-Z0-9_.]+)\s*(==|!=|>=|<=|>|<)\s*(.+)$", term.strip())
        if not m:
            return None
        field = str(m.group(1) or "").strip().lower()
        op = str(m.group(2) or "").strip()
        value = str(m.group(3) or "").strip().strip("'").strip('"')
        return field, op, value

    def _match_packet_term(self, row: dict, term: str) -> bool:
        t = term.strip().lower()
        if not t:
            return True
        if t in {"tcp", "udp", "icmp"}:
            return str(row.get("proto", "")).lower() == t
        m_contains = re.match(r"^([a-zA-Z0-9_.]+)\s+contains\s+(.+)$", t)
        if m_contains:
            field = str(m_contains.group(1) or "").strip()
            value = str(m_contains.group(2) or "").strip().strip("'").strip('"')
            source_text = ""
            if field in {"process", "process_name"}:
                source_text = str(row.get("process_name", ""))
            elif field in {"ip", "ip.addr"}:
                source_text = f"{row.get('src_ip', '')} {row.get('dst_ip', '')}"
            elif field in {"proto", "source", "risk"}:
                source_text = str(row.get("risk_level" if field == "risk" else field, ""))
            else:
                source_text = str(row.get(field, ""))
            return value.lower() in source_text.lower()
        parsed = self._parse_rule_term(t)
        if not parsed:
            flat = " ".join(
                [
                    str(row.get("src_ip", "")),
                    str(row.get("dst_ip", "")),
                    str(row.get("proto", "")),
                    str(row.get("process_name", "")),
                    str(row.get("source", "")),
                ]
            ).lower()
            return t in flat
        field, op, expected_raw = parsed
        expected_num = None
        try:
            expected_num = float(expected_raw)
        except Exception:
            expected_num = None
        if field in {"ip.src", "src_ip"}:
            values = [str(row.get("src_ip", ""))]
        elif field in {"ip.dst", "dst_ip"}:
            values = [str(row.get("dst_ip", ""))]
        elif field in {"ip.addr", "ip"}:
            values = [str(row.get("src_ip", "")), str(row.get("dst_ip", ""))]
        elif field in {"port", "tcp.port", "udp.port"}:
            values = [int(row.get("src_port", 0) or 0), int(row.get("dst_port", 0) or 0)]
        elif field in {"tcp.srcport", "udp.srcport", "src_port"}:
            values = [int(row.get("src_port", 0) or 0)]
        elif field in {"tcp.dstport", "udp.dstport", "dst_port"}:
            values = [int(row.get("dst_port", 0) or 0)]
        elif field in {"frame.len", "len", "length"}:
            values = [int(row.get("length", 0) or 0)]
        elif field in {"frame.number", "no"}:
            values = [int(row.get("id", 0) or 0)]
        elif field in {"frame.time_delta", "delta"}:
            values = [float(row.get("ts_epoch", 0.0) or 0.0)]
        elif field in {"risk", "risk_level"}:
            values = [str(row.get("risk_level", ""))]
        elif field in {"process", "process_name"}:
            values = [str(row.get("process_name", ""))]
        elif field in {"proto", "source", "id", "ts", "time"}:
            key = "ts" if field in {"ts", "time"} else field
            values = [row.get(key, "")]
        else:
            values = [row.get(field, "")]

        def compare_one(v) -> bool:
            if expected_num is not None:
                try:
                    actual_num = float(v)
                except Exception:
                    return False
                if op == "==":
                    return actual_num == expected_num
                if op == "!=":
                    return actual_num != expected_num
                if op == ">":
                    return actual_num > expected_num
                if op == "<":
                    return actual_num < expected_num
                if op == ">=":
                    return actual_num >= expected_num
                if op == "<=":
                    return actual_num <= expected_num
                return False
            actual = str(v).lower()
            expected = expected_raw.lower()
            if op == "==":
                return actual == expected
            if op == "!=":
                return actual != expected
            if op == ">":
                return actual > expected
            if op == "<":
                return actual < expected
            if op == ">=":
                return actual >= expected
            if op == "<=":
                return actual <= expected
            return False

        if op == "!=":
            return all(compare_one(v) for v in values)
        return any(compare_one(v) for v in values)

    def _packet_match_rule(self, row: dict, expression: str) -> bool:
        expr = expression.strip()
        if not expr:
            return True
        or_parts = [p.strip() for p in expr.split("||") if p.strip()]
        if not or_parts:
            return True
        for or_part in or_parts:
            and_parts = [p.strip() for p in or_part.split("&&") if p.strip()]
            ok = True
            for raw_term in and_parts:
                term = raw_term
                negate = False
                while term.startswith("!"):
                    negate = not negate
                    term = term[1:].strip()
                term_ok = self._match_packet_term(row, term)
                if negate:
                    term_ok = not term_ok
                if not term_ok:
                    ok = False
                    break
            if ok:
                return True
        return False

    def load_packets(self) -> None:
        if not self.is_authenticated:
            return
        self._cancel_packet_render()
        self._packet_load_token += 1
        token = self._packet_load_token
        process_name = self.packet_filter_process_var.get().strip()
        ip = self.packet_filter_ip_var.get().strip()
        source = self.packet_filter_source_var.get()
        expr = self.packet_rule_expr_var.get().strip()
        only_abnormal = self.packet_only_abnormal_var.get()
        sort_key = self.packet_sort_key_var.get().strip() or "ts"
        sort_desc = self.packet_sort_desc_var.get()
        self._packet_rows_in_view = []
        self._packet_time_base = 0.0
        self._current_packet_detail = None
        self._packet_tree_id_map.clear()
        for i in self.packet_tree.get_children():
            self.packet_tree.delete(i)
        for i in self.packet_detail_tree.get_children():
            self.packet_detail_tree.delete(i)
        self.packet_expert_text.configure(state=tk.NORMAL)
        self.packet_expert_text.delete("1.0", tk.END)
        self.packet_expert_text.insert("1.0", "Expert Info:\n- 选择一条流量记录后显示分析结论。")
        self.packet_expert_text.configure(state=tk.DISABLED)
        self.packet_detail_text.configure(state=tk.NORMAL)
        self.packet_detail_text.delete("1.0", tk.END)
        self.packet_detail_text.insert("1.0", "选择一条流量记录可查看分层详情与原始字节。")
        self.packet_detail_text.configure(state=tk.DISABLED)
        self.packet_import_status_var.set("流量窗口加载中: 正在查询并准备渲染...")
        self._packet_query_done = False
        self._packet_query_error = ""
        self._packet_query_result = []

        def worker() -> None:
            try:
                rows = self.runtime.query_packets(
                    limit=None,
                    process_name=process_name,
                    ip=ip,
                    source=source,
                    rule_expr=expr,
                )
                if expr:
                    rows = [r for r in rows if self._packet_match_rule(r, expr)]
                if only_abnormal:
                    rows = [r for r in rows if str(r.get("risk_level", "normal")).lower() != "normal"]
                rows.sort(key=lambda r: self._packet_sort_value(r, sort_key), reverse=sort_desc)
                self._packet_query_result = rows
            except Exception as e:
                self._packet_query_error = str(e)
            finally:
                self._packet_query_done = True

        self._packet_query_thread = threading.Thread(target=worker, daemon=True)
        self._packet_query_thread.start()
        self.root.after(60, lambda: self._poll_packet_query(token, source))

    def _cancel_packet_render(self) -> None:
        if self._packet_render_job:
            self.root.after_cancel(self._packet_render_job)
            self._packet_render_job = None
        if self._packet_virtual_render_job:
            self.root.after_cancel(self._packet_virtual_render_job)
            self._packet_virtual_render_job = None
        self._packet_virtual_enabled = False
        self._packet_virtual_window_start = 0
        self._packet_detail_query_token += 1

    def _on_packet_tree_yscroll(self, first: str, last: str) -> None:
        if not self.packet_tree_y_scroll:
            return
        if not self._packet_virtual_enabled:
            self.packet_tree_y_scroll.set(first, last)
            return
        total = len(self._packet_rows_in_view)
        if total <= 0:
            self.packet_tree_y_scroll.set(0.0, 1.0)
            return
        self._update_packet_virtual_scrollbar()

    def _update_packet_virtual_scrollbar(self) -> None:
        if not self.packet_tree_y_scroll:
            return
        total = len(self._packet_rows_in_view)
        if total <= 0:
            self.packet_tree_y_scroll.set(0.0, 1.0)
            return
        window = min(self._packet_virtual_window_size, total)
        first = max(0.0, min(1.0, float(self._packet_virtual_window_start) / float(total)))
        logical_span = float(window) / float(total)
        # Tk 的滑块太小时几乎看不出移动，设置一个可见最小宽度提升可操作性。
        span = max(logical_span, 0.02)
        last = max(first + 0.001, min(1.0, first + span))
        if last <= first:
            last = min(1.0, first + 0.001)
        self.packet_tree_y_scroll.set(first, last)

    def _on_packet_tree_yview(self, *args) -> None:
        if not self._packet_virtual_enabled:
            self.packet_tree.yview(*args)
            return
        total = len(self._packet_rows_in_view)
        if total <= 0:
            return
        max_start = max(0, total - self._packet_virtual_window_size)
        start = self._packet_virtual_window_start
        if not args:
            return
        cmd = str(args[0]).strip().lower()
        immediate = False
        if cmd == "moveto" and len(args) >= 2:
            frac = max(0.0, min(1.0, float(args[1])))
            start = int(frac * max_start)
            immediate = True
        elif cmd == "scroll" and len(args) >= 3:
            step = int(args[1])
            unit = str(args[2]).strip().lower()
            delta = max(20, self._packet_virtual_window_size // 4) if unit == "pages" else 12
            start = start + step * delta
        start = max(0, min(max_start, start))
        self._schedule_packet_virtual_render(start, keep_selected=True, immediate=immediate)

    def _on_packet_tree_mousewheel(self, event) -> str | None:
        if not self._packet_virtual_enabled:
            return None
        delta = 0
        if hasattr(event, "delta") and event.delta:
            delta = -1 if int(event.delta) > 0 else 1
        elif getattr(event, "num", 0) == 4:
            delta = -1
        elif getattr(event, "num", 0) == 5:
            delta = 1
        if delta != 0:
            self._on_packet_tree_yview("scroll", delta, "units")
            return "break"
        return None

    def _poll_packet_query(self, token: int, source_filter: str) -> None:
        if token != self._packet_load_token:
            return
        if not self._packet_query_done:
            self._packet_render_job = self.root.after(80, lambda: self._poll_packet_query(token, source_filter))
            return
        self._packet_render_job = None
        if self._packet_query_error:
            self.packet_import_status_var.set("流量窗口加载失败")
            messagebox.showerror("ERR_QUERY", self._packet_query_error)
            return
        rows = list(self._packet_query_result)
        self._packet_query_result = []
        self._packet_rows_in_view = rows
        ts_epochs = [float(r.get("ts_epoch", 0.0) or 0.0) for r in rows if float(r.get("ts_epoch", 0.0) or 0.0) > 0]
        self._packet_time_base = min(ts_epochs) if ts_epochs else 0.0
        self._packet_detail_cache.clear()
        self._packet_detail_cache_order.clear()
        offline_view = str(source_filter).strip().lower() == "offline"
        self.packet_import_status_var.set(f"流量窗口加载中: 0/{len(rows)}")
        if len(rows) > self._packet_virtual_threshold:
            self._packet_virtual_enabled = True
            self._packet_virtual_window_start = 0
            self._schedule_packet_virtual_render(0, keep_selected=False, immediate=True)
            return
        self._render_packet_rows_chunk(token=token, rows=rows, start=0, offline_view=offline_view)

    def _schedule_packet_virtual_render(self, start: int, keep_selected: bool, immediate: bool = False) -> None:
        self._packet_virtual_pending_start = int(start)
        self._packet_virtual_pending_keep_selected = bool(keep_selected)
        if self._packet_virtual_render_job:
            self.root.after_cancel(self._packet_virtual_render_job)
            self._packet_virtual_render_job = None
        delay = 0 if immediate else 12
        self._packet_virtual_render_job = self.root.after(delay, self._flush_packet_virtual_render)

    def _flush_packet_virtual_render(self) -> None:
        self._packet_virtual_render_job = None
        self._render_packet_virtual_window(
            start=self._packet_virtual_pending_start,
            keep_selected=self._packet_virtual_pending_keep_selected,
        )

    def _insert_packet_tree_row(self, idx: int, row: dict, offline_view: bool) -> tuple[str, int]:
        parity = "even" if idx % 2 == 0 else "odd"
        risk = str(row.get("risk_level", "normal")).lower()
        risk_tag = "lvl_high" if risk == "high" else ("lvl_medium" if risk == "medium" else "")
        proto = str(row.get("proto", "") or "").upper()
        src_port = int(row.get("src_port", 0) or 0)
        dst_port = int(row.get("dst_port", 0) or 0)
        proto_tag = ""
        if proto == "TCP" and (src_port in {80, 8080, 8000} or dst_port in {80, 8080, 8000}):
            proto_tag = "proto_http"
        elif (src_port == 53 or dst_port == 53) and proto in {"TCP", "UDP"}:
            proto_tag = "proto_dns"
        elif proto == "TCP" and (src_port in {443, 8443} or dst_port in {443, 8443}):
            proto_tag = "proto_tls"
        tags = tuple([parity] + ([proto_tag] if proto_tag else []) + ([risk_tag] if risk_tag else []))
        db_id = int(row["id"])
        display_no = idx + 1
        delta_text = self._packet_delta_text(float(row.get("ts_epoch", 0.0) or 0.0))
        info_text = self._build_packet_info_summary(row)
        item_id = self.packet_tree.insert(
            "",
            tk.END,
            values=(
                display_no,
                delta_text,
                row["ts"],
                row.get("source", ""),
                row.get("risk_level", "normal"),
                row["src_ip"],
                row.get("src_port", 0),
                row["dst_ip"],
                row.get("dst_port", 0),
                row.get("proto", ""),
                row.get("length", 0),
                info_text,
            ),
            tags=tags,
        )
        self._packet_tree_id_map[item_id] = db_id
        return item_id, db_id

    def _packet_delta_text(self, ts_epoch: float) -> str:
        if ts_epoch <= 0 or self._packet_time_base <= 0:
            return "0.000000"
        delta = max(0.0, float(ts_epoch) - float(self._packet_time_base))
        return f"{delta:.6f}"

    def _build_packet_info_summary(self, row: dict) -> str:
        proto = str(row.get("proto", "") or "").upper()
        src_ip = str(row.get("src_ip", "") or "")
        dst_ip = str(row.get("dst_ip", "") or "")
        src_port = int(row.get("src_port", 0) or 0)
        dst_port = int(row.get("dst_port", 0) or 0)
        length = int(row.get("length", 0) or 0)
        process_name = str(row.get("process_name", "") or "").strip()
        direction = str(row.get("direction", "") or "").strip()
        if proto == "TCP":
            app = ""
            if dst_port in {80, 8080, 8000} or src_port in {80, 8080, 8000}:
                app = "HTTP?"
            elif dst_port in {443, 8443} or src_port in {443, 8443}:
                app = "TLS?"
            elif dst_port == 53 or src_port == 53:
                app = "DNS?"
            return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  TCP Len={length} {app}".strip()
        if proto == "UDP":
            app = "DNS?" if (dst_port == 53 or src_port == 53) else ""
            return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  UDP Len={length} {app}".strip()
        if proto == "ICMP":
            return f"{src_ip} -> {dst_ip}  ICMP Len={length}"
        hints = []
        if process_name:
            hints.append(process_name)
        if direction:
            hints.append(direction)
        hint_text = f" [{' / '.join(hints)}]" if hints else ""
        return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  {proto or 'OTHER'} Len={length}{hint_text}"

    def _render_packet_virtual_window(self, start: int, keep_selected: bool) -> None:
        total = len(self._packet_rows_in_view)
        if total <= 0:
            self.packet_import_status_var.set("流量窗口已完成: 0 条")
            return
        start = max(0, min(max(0, total - self._packet_virtual_window_size), int(start)))
        if start == self._packet_virtual_window_start and keep_selected:
            return
        end = min(total, start + self._packet_virtual_window_size)
        selected_id = None
        if keep_selected:
            selected = self.packet_tree.selection()
            if selected:
                selected_id = self._packet_tree_db_id(selected[0])
        source_filter = self.packet_filter_source_var.get().strip().lower()
        offline_view = source_filter == "offline"
        self._packet_virtual_window_start = start
        self._packet_tree_id_map.clear()
        for i in self.packet_tree.get_children():
            self.packet_tree.delete(i)
        for idx in range(start, end):
            item_id, db_id = self._insert_packet_tree_row(idx=idx, row=self._packet_rows_in_view[idx], offline_view=offline_view)
            if selected_id is not None and db_id == selected_id:
                self.packet_tree.selection_set(item_id)
                self.packet_tree.focus(item_id)
        self.packet_import_status_var.set(f"流量窗口虚拟渲染: 总 {total} 条 | 当前 {start + 1}-{end}")
        self.packet_tree.yview_moveto(0.0)
        self._update_packet_virtual_scrollbar()

    def _render_packet_rows_chunk(self, token: int, rows: list[dict], start: int, offline_view: bool) -> None:
        if token != self._packet_load_token:
            return
        end = min(start + self._packet_render_chunk_size, len(rows))
        for idx in range(start, end):
            self._insert_packet_tree_row(idx=idx, row=rows[idx], offline_view=offline_view)
        self.packet_import_status_var.set(f"流量窗口加载中: {end}/{len(rows)}")
        if end < len(rows):
            self._packet_render_job = self.root.after(
                1,
                lambda: self._render_packet_rows_chunk(token=token, rows=rows, start=end, offline_view=offline_view),
            )
            return
        self._packet_render_job = None
        self.packet_import_status_var.set(f"流量窗口已完成: {len(rows)} 条")

    def _packet_tree_db_id(self, item_id: str) -> int:
        real_id = self._packet_tree_id_map.get(item_id)
        if real_id is not None:
            return int(real_id)
        raise KeyError(f"packet tree id map missing for item {item_id}")

    def _get_cached_packet_detail(self, packet_id: int) -> dict | None:
        pid = int(packet_id)
        detail = self._packet_detail_cache.get(pid)
        if detail is None:
            return None
        if pid in self._packet_detail_cache_order:
            self._packet_detail_cache_order.remove(pid)
            self._packet_detail_cache_order.append(pid)
        return detail

    def _put_cached_packet_detail(self, packet_id: int, detail: dict) -> None:
        pid = int(packet_id)
        if pid in self._packet_detail_cache_order:
            self._packet_detail_cache_order.remove(pid)
        self._packet_detail_cache[pid] = detail
        self._packet_detail_cache_order.append(pid)
        while len(self._packet_detail_cache_order) > self._packet_detail_cache_max:
            old = self._packet_detail_cache_order.pop(0)
            if old in self._packet_detail_cache:
                self._packet_detail_cache.pop(old, None)

    def _decode_raw_bytes(self, raw_hex: str) -> bytes:
        text = str(raw_hex or "").strip()
        if not text:
            return b""
        try:
            return bytes.fromhex(text)
        except Exception:
            return b""

    def _extract_ascii(self, raw_bytes: bytes) -> str:
        if not raw_bytes:
            return ""
        return "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)

    def _extract_http_line(self, raw_bytes: bytes) -> str:
        if not raw_bytes:
            return ""
        try:
            text = raw_bytes.decode("latin-1", errors="ignore")
        except Exception:
            return ""
        first = text.splitlines()[0].strip() if text else ""
        if not first:
            return ""
        methods = ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/")
        for m in methods:
            if first.upper().startswith(m):
                return first[:180]
        return ""

    def _is_private_ip(self, ip_text: str) -> bool:
        try:
            return ipaddress.ip_address(str(ip_text)).is_private
        except Exception:
            return False

    def _build_expert_findings(self, detail: dict, risk_value: str, alerts: list[dict]) -> list[str]:
        findings: list[str] = []
        proto = str(detail.get("proto", "") or "").upper()
        src_ip = str(detail.get("src_ip", "") or "")
        dst_ip = str(detail.get("dst_ip", "") or "")
        src_port = int(detail.get("src_port", 0) or 0)
        dst_port = int(detail.get("dst_port", 0) or 0)
        raw_bytes = self._decode_raw_bytes(str(detail.get("raw_hex", "")))
        ascii_preview = self._extract_ascii(raw_bytes).lower()
        http_line = self._extract_http_line(raw_bytes)

        if str(risk_value).lower() in {"high", "medium"}:
            findings.append(f"[{str(risk_value).upper()}] 当前流量已被风险关联标记。")
        if alerts:
            findings.append(f"关联告警 {len(alerts)} 条，最近子类: {alerts[0].get('sub_category', '')}")
        if http_line:
            findings.append(f"HTTP首行: {http_line}")
        if proto == "TCP" and (src_port in {21, 23, 110, 143} or dst_port in {21, 23, 110, 143}):
            findings.append("检测到明文协议常见端口（FTP/Telnet/POP3/IMAP），存在凭据泄露风险。")
        keyword_hits = [k for k in ["password", "passwd", "token", "authorization", "union select", "cmd=", "powershell"] if k in ascii_preview]
        if keyword_hits:
            findings.append(f"载荷命中敏感关键词: {', '.join(keyword_hits[:5])}")
        if self._is_private_ip(src_ip) and (not self._is_private_ip(dst_ip)):
            findings.append("流向特征: 私网 -> 公网，可关注外联/外传行为。")
        if proto in {"UDP", "TCP"} and (src_port == 53 or dst_port == 53):
            findings.append("检测到DNS通道，可进一步按域名/长度分布排查隧道行为。")
        if not findings:
            findings.append("未发现明显异常启发式特征，建议结合会话追踪与过滤器进一步排查。")
        return findings

    def _render_packet_expert_info(self, detail: dict, risk_value: str, alerts: list[dict]) -> None:
        findings = self._build_expert_findings(detail, risk_value, alerts)
        lines = ["Expert Info:"] + [f"- {line}" for line in findings]
        self.packet_expert_text.configure(state=tk.NORMAL)
        self.packet_expert_text.delete("1.0", tk.END)
        self.packet_expert_text.insert("1.0", "\n".join(lines))
        self.packet_expert_text.configure(state=tk.DISABLED)

    def _decode_raw_by_mode(self, raw_hex: str, mode: str) -> str:
        m = str(mode or "").strip().lower()
        raw_bytes = self._decode_raw_bytes(raw_hex)
        if not raw_bytes:
            return "(empty)"
        if m == "ascii":
            text = self._extract_ascii(raw_bytes)
            return "\n".join(text[i : i + 120] for i in range(0, len(text), 120))
        if m == "utf-8":
            text = raw_bytes.decode("utf-8", errors="replace")
            return "\n".join(text[i : i + 120] for i in range(0, len(text), 120))
        if m == "base64":
            text = base64.b64encode(raw_bytes).decode("ascii")
            return "\n".join(text[i : i + 96] for i in range(0, len(text), 96))
        return self._format_hex_dump(raw_hex)

    def _render_current_packet_raw(self) -> None:
        if not self._current_packet_detail:
            return
        raw_hex = str(self._current_packet_detail.get("raw_hex", ""))
        mode = self.packet_raw_mode_var.get().strip().lower()
        content = self._decode_raw_by_mode(raw_hex, mode)
        self.packet_detail_text.configure(state=tk.NORMAL)
        self.packet_detail_text.delete("1.0", tk.END)
        self.packet_detail_text.insert("1.0", content)
        self.packet_detail_text.configure(state=tk.DISABLED)

    def _render_packet_detail_tree(self, detail: dict, risk_value: str, alerts: list[dict]) -> None:
        for i in self.packet_detail_tree.get_children():
            self.packet_detail_tree.delete(i)
        frame_node = self.packet_detail_tree.insert("", tk.END, text="Frame", values=(f"ID={detail.get('id')}  TIME={detail.get('ts', '')}",))
        self.packet_detail_tree.insert(frame_node, tk.END, text="Length", values=(str(detail.get("length", 0)),))
        self.packet_detail_tree.insert(frame_node, tk.END, text="Source", values=(str(detail.get("source", "")),))
        ip_node = self.packet_detail_tree.insert("", tk.END, text="Internet Protocol", values=(f"{detail.get('src_ip', '')} -> {detail.get('dst_ip', '')}",))
        self.packet_detail_tree.insert(ip_node, tk.END, text="Source IP", values=(str(detail.get("src_ip", "")),))
        self.packet_detail_tree.insert(ip_node, tk.END, text="Destination IP", values=(str(detail.get("dst_ip", "")),))
        proto = str(detail.get("proto", "") or "").upper()
        l4_node = self.packet_detail_tree.insert(
            "",
            tk.END,
            text=f"Transport ({proto or 'OTHER'})",
            values=(f"{detail.get('src_port', 0)} -> {detail.get('dst_port', 0)}",),
        )
        self.packet_detail_tree.insert(l4_node, tk.END, text="Source Port", values=(str(detail.get("src_port", 0)),))
        self.packet_detail_tree.insert(l4_node, tk.END, text="Destination Port", values=(str(detail.get("dst_port", 0)),))
        raw_bytes = self._decode_raw_bytes(str(detail.get("raw_hex", "")))
        http_line = self._extract_http_line(raw_bytes)
        if http_line:
            app_node = self.packet_detail_tree.insert("", tk.END, text="Application (HTTP heuristic)", values=(http_line,))
            self.packet_detail_tree.insert(app_node, tk.END, text="First Line", values=(http_line,))
        elif int(detail.get("src_port", 0) or 0) == 53 or int(detail.get("dst_port", 0) or 0) == 53:
            self.packet_detail_tree.insert("", tk.END, text="Application (DNS heuristic)", values=("Detected by port 53",))
        elif int(detail.get("src_port", 0) or 0) in {443, 8443} or int(detail.get("dst_port", 0) or 0) in {443, 8443}:
            self.packet_detail_tree.insert("", tk.END, text="Application (TLS heuristic)", values=("Detected by TLS common ports",))
        sec_node = self.packet_detail_tree.insert("", tk.END, text="Security", values=(f"Risk={risk_value}",))
        self.packet_detail_tree.insert(sec_node, tk.END, text="Related Alerts", values=(str(len(alerts)),))
        for row in alerts[:8]:
            self.packet_detail_tree.insert(
                sec_node,
                tk.END,
                text=f"[{row.get('level', '')}] {row.get('sub_category', '')}",
                values=(f"{row.get('ts', '')} {row.get('reason', '')}",),
            )
        self.packet_detail_tree.item(frame_node, open=True)
        self.packet_detail_tree.item(ip_node, open=True)
        self.packet_detail_tree.item(l4_node, open=True)
        self.packet_detail_tree.item(sec_node, open=True)

    def _render_packet_detail(self, detail: dict, values: tuple | list | None = None) -> None:
        row_values = values or ()
        risk_value = row_values[4] if len(row_values) > 4 else str(detail.get("risk_level", "normal"))
        alerts = detail.get("related_alerts", [])
        self._current_packet_detail = detail
        self._render_packet_detail_tree(detail, risk_value, alerts)
        self._render_packet_expert_info(detail, risk_value, alerts)
        self._render_current_packet_raw()

    def open_follow_stream_viewer(self) -> None:
        selected = self.packet_tree.selection()
        if not selected:
            messagebox.showwarning("ERR_INPUT", "请先选择一条流量记录。")
            return
        packet_id = self._packet_tree_db_id(selected[0])
        self.packet_import_status_var.set(f"流量窗口加载中: 正在追踪会话 ID={packet_id} ...")
        rows = self.runtime.query_flow_packets(packet_id, limit=3000)
        if not rows:
            messagebox.showwarning("ERR_DATA", "未找到该包对应的会话流。")
            return
        first = rows[0]
        anchor_src = str(first.get("src_ip", ""))
        anchor_sport = int(first.get("src_port", 0) or 0)
        title = f"会话追踪 {first.get('proto', '')} {first.get('src_ip', '')}:{first.get('src_port', 0)} <-> {first.get('dst_ip', '')}:{first.get('dst_port', 0)}"
        dlg = tk.Toplevel(self.root)
        dlg.title(title)
        dlg.geometry("1200x760")
        dlg.minsize(980, 640)
        mode_var = tk.StringVar(value="ascii")
        tip_var = tk.StringVar(value=f"共 {len(rows)} 条，会话按时间升序显示。")
        top = ttk.Frame(dlg)
        top.pack(fill=tk.X, padx=8, pady=8)
        ttk.Label(top, text="[MODE] Stream编码", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Combobox(top, textvariable=mode_var, values=["ascii", "utf-8", "hex", "base64"], width=12, state="readonly").pack(side=tk.LEFT, padx=6)
        ttk.Label(top, textvariable=tip_var, style="Path.TLabel").pack(side=tk.LEFT, padx=8)
        text = tk.Text(dlg, bg="#F5F7FA", fg="#003366", insertbackground="#003366", relief=tk.SOLID, borderwidth=1, font=self.font_mono, wrap=tk.NONE)
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        def render() -> None:
            mode = mode_var.get().strip().lower()
            lines: list[str] = []
            for idx, row in enumerate(rows, start=1):
                src = str(row.get("src_ip", ""))
                dst = str(row.get("dst_ip", ""))
                sport = int(row.get("src_port", 0) or 0)
                dport = int(row.get("dst_port", 0) or 0)
                direction = "C->S" if (src == anchor_src and sport == anchor_sport) else "S->C"
                head = f"[{idx:04d}] {row.get('ts', '')} {direction} {src}:{sport} -> {dst}:{dport} LEN={row.get('length', 0)}"
                payload = self._decode_raw_by_mode(str(row.get("raw_hex", "")), mode)
                lines.append(head)
                lines.append(payload if payload else "(empty)")
                lines.append("")
            text.configure(state=tk.NORMAL)
            text.delete("1.0", tk.END)
            text.insert("1.0", "\n".join(lines))
            text.configure(state=tk.DISABLED)

        mode_var.trace_add("write", lambda *_: render())
        render()
        self.packet_import_status_var.set(f"流量窗口会话追踪完成: {len(rows)} 条")

    def import_offline_pcap(self) -> None:
        if not self._require_admin():
            return
        picked = filedialog.askopenfilename(title="选择PCAP文件", filetypes=[("Pcap files", "*.pcap *.pcapng"), ("All files", "*.*")])
        if not picked:
            return
        if self._offline_import_thread and self._offline_import_thread.is_alive():
            messagebox.showwarning("ERR_STATE", "已有离线分析任务在运行。")
            return
        target = Path(picked)
        self._cancel_packet_render()
        self._packet_load_token += 1
        # 离线导入只展示离线源，避免与实时流量混淆。
        self.packet_filter_source_var.set("offline")
        self._packet_virtual_enabled = False
        self._packet_virtual_window_start = 0
        self._packet_rows_in_view = []
        for i in self.packet_tree.get_children():
            self.packet_tree.delete(i)
        for i in self.packet_detail_tree.get_children():
            self.packet_detail_tree.delete(i)
        self.packet_expert_text.configure(state=tk.NORMAL)
        self.packet_expert_text.delete("1.0", tk.END)
        self.packet_expert_text.insert("1.0", "Expert Info:\n- 选择一条流量记录后显示分析结论。")
        self.packet_expert_text.configure(state=tk.DISABLED)
        self.packet_detail_text.configure(state=tk.NORMAL)
        self.packet_detail_text.delete("1.0", tk.END)
        self.packet_detail_text.insert("1.0", "选择一条流量记录可查看分层详情与原始字节。")
        self.packet_detail_text.configure(state=tk.DISABLED)
        self._current_packet_detail = None
        self._offline_import_done = False
        self._offline_import_error = ""
        mode = self.offline_mode_var.get().strip().lower() or "balanced"
        profile = self.runtime.get_offline_import_profile(mode)
        self.packet_import_status_var.set(
            f"离线分析状态: 正在处理 {target.name} | mode={profile.mode} | threads={profile.parser_threads} | cpu_limit={profile.cpu_limit_percent}%"
        )
        self._offline_import_thread = threading.Thread(target=self._offline_import_worker, args=(target, mode), daemon=True)
        self._offline_import_thread.start()
        self.root.after(300, self._poll_offline_import)

    def _offline_import_worker(self, target: Path, mode: str) -> None:
        try:
            self._offline_import_result = self.runtime.import_offline_pcap(target, mode=mode)
        except Exception as e:
            self._offline_import_error = str(e)
        finally:
            self._offline_import_done = True

    def _poll_offline_import(self) -> None:
        progress = self.runtime.offline_progress
        if bool(progress.get("running", False)):
            pct = float(progress.get("percent", 0.0))
            mode = str(progress.get("mode", "balanced"))
            parser_threads = int(progress.get("parser_threads", 1) or 1)
            cpu_limit = int(progress.get("cpu_limit_percent", 0) or 0)
            self.packet_progress_var.set(pct)
            self.packet_import_status_var.set(
                f"离线分析状态: {pct:.1f}% | mode={mode} | threads={parser_threads} | cpu_limit={cpu_limit}% | 已处理 {progress.get('processed', 0)} 包 | 已识别告警 {progress.get('alerts', 0)}"
            )
        if not self._offline_import_done:
            self.root.after(300, self._poll_offline_import)
            return
        if self._offline_import_error:
            self.packet_import_status_var.set("离线分析状态: 失败")
            messagebox.showerror("ERR_PCAP", self._offline_import_error)
            return
        packets, alerts = self._offline_import_result
        mode = str(self.runtime.offline_progress.get("mode", "balanced"))
        self.packet_progress_var.set(100.0)
        self.packet_import_status_var.set(f"离线分析状态: 完成，mode={mode}, packets={packets}, alerts={alerts}")
        file_name = str(self.runtime.offline_progress.get("file", ""))
        self.runtime.audit.log(self.username, "offline_pcap_import", file_name, f"mode={mode},packets={packets},alerts={alerts}")
        self.load_packets()
        self.load_alerts()
        messagebox.showinfo("OK", f"离线分析完成：mode={mode}, packets={packets}, alerts={alerts}")

    def _selected_packet_rows(self) -> list[dict]:
        selected = self.packet_tree.selection()
        if not selected:
            return list(self._packet_rows_in_view[:300])
        ids = [self._packet_tree_db_id(item) for item in selected]
        return self.runtime.query_packets_by_ids(ids)

    def _on_packet_double_click(self, _event=None) -> None:
        rows = self._selected_packet_rows()
        if not rows:
            messagebox.showwarning("ERR_INPUT", "没有可导出的流量记录。")
            return
        self._open_export_dialog(rows)

    def open_packet_raw_viewer(self) -> None:
        selected = self.packet_tree.selection()
        if not selected:
            messagebox.showwarning("ERR_INPUT", "请先选择一条流量记录。")
            return
        packet_ids = [int(r.get("id", 0) or 0) for r in self._packet_rows_in_view if int(r.get("id", 0) or 0) > 0]
        if not packet_ids:
            messagebox.showwarning("ERR_DATA", "当前过滤条件下无可查看流量。")
            return
        current_id = self._packet_tree_db_id(selected[0])
        if current_id not in packet_ids:
            return
        state = {"index": packet_ids.index(current_id)}
        dlg = tk.Toplevel(self.root)
        dlg.title("原始流量查看器")
        dlg.geometry("1100x700")
        dlg.minsize(900, 560)
        mode_var = tk.StringVar(value="hex")
        pos_var = tk.StringVar(value="")
        bar = ttk.Frame(dlg)
        bar.pack(fill=tk.X, padx=8, pady=8)
        prev_btn = ttk.Button(bar, text="[PREV] 上一个")
        prev_btn.pack(side=tk.LEFT, padx=(0, 6))
        next_btn = ttk.Button(bar, text="[NEXT] 下一个")
        next_btn.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Label(bar, text="[ENC] 编码", style="Hint.TLabel").pack(side=tk.LEFT)
        ttk.Combobox(bar, textvariable=mode_var, values=["hex", "ascii", "utf-8", "base64"], width=12, state="readonly").pack(side=tk.LEFT, padx=6)
        ttk.Label(bar, textvariable=pos_var, style="Path.TLabel").pack(side=tk.RIGHT)
        text = tk.Text(dlg, bg="#F5F7FA", fg="#003366", insertbackground="#003366", relief=tk.SOLID, borderwidth=1, font=self.font_mono, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        def wrap_plain(content: str, width: int) -> str:
            if not content:
                return ""
            lines: list[str] = []
            for raw_line in content.splitlines() or [content]:
                line = raw_line
                if not line:
                    lines.append("")
                    continue
                for i in range(0, len(line), width):
                    lines.append(line[i : i + width])
            return "\n".join(lines)

        def decode(raw_hex: str, mode: str) -> str:
            m = mode.strip().lower()
            try:
                raw_bytes = bytes.fromhex(raw_hex)
            except Exception:
                raw_bytes = b""
            if m == "ascii":
                ascii_text = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw_bytes)
                return wrap_plain(ascii_text, 120)
            if m == "utf-8":
                utf8_text = raw_bytes.decode("utf-8", errors="replace")
                return wrap_plain(utf8_text, 120)
            if m == "base64":
                b64 = base64.b64encode(raw_bytes).decode("ascii") if raw_bytes else ""
                return wrap_plain(b64, 96)
            return self._format_hex_dump(raw_hex)

        def render() -> None:
            packet_id = packet_ids[state["index"]]
            detail = self._get_cached_packet_detail(packet_id)
            if detail is None:
                detail = self.runtime.query_packet_detail(packet_id)
                if detail:
                    self._put_cached_packet_detail(packet_id, detail)
            if not detail:
                return
            raw_hex = str(detail.get("raw_hex", ""))
            mode = mode_var.get().strip().lower()
            shown = decode(raw_hex, mode)
            pos_var.set(f"[{state['index'] + 1}/{len(packet_ids)}] ID={packet_id}  {detail.get('src_ip', '')}:{detail.get('src_port', 0)} -> {detail.get('dst_ip', '')}:{detail.get('dst_port', 0)}  {detail.get('proto', '')}")
            text.configure(state=tk.NORMAL)
            text.delete("1.0", tk.END)
            text.insert("1.0", shown if shown else "(empty)")
            text.configure(state=tk.DISABLED)
            prev_btn.configure(state=tk.NORMAL if state["index"] > 0 else tk.DISABLED)
            next_btn.configure(state=tk.NORMAL if state["index"] < len(packet_ids) - 1 else tk.DISABLED)

        def to_prev(_event=None) -> None:
            if state["index"] <= 0:
                return
            state["index"] -= 1
            render()

        def to_next(_event=None) -> None:
            if state["index"] >= len(packet_ids) - 1:
                return
            state["index"] += 1
            render()

        prev_btn.configure(command=to_prev)
        next_btn.configure(command=to_next)
        dlg.bind("<Left>", to_prev)
        dlg.bind("<Right>", to_next)
        dlg.bind("<Up>", to_prev)
        dlg.bind("<Down>", to_next)
        mode_var.trace_add("write", lambda *_: render())
        render()

    def _on_packet_select(self, _event=None) -> None:
        selected = self.packet_tree.selection()
        if not selected:
            return
        values = self.packet_tree.item(selected[0], "values")
        packet_id = self._packet_tree_db_id(selected[0])
        cached = self._get_cached_packet_detail(packet_id)
        if cached:
            self._render_packet_detail(cached, values)
            return
        self.packet_detail_text.configure(state=tk.NORMAL)
        self.packet_detail_text.delete("1.0", tk.END)
        self.packet_detail_text.insert("1.0", f"正在加载详情... ID={packet_id}")
        self.packet_detail_text.configure(state=tk.DISABLED)
        self._packet_detail_query_token += 1
        token = self._packet_detail_query_token
        result: dict[str, object] = {"detail": None, "error": ""}

        def worker() -> None:
            try:
                detail = self.runtime.query_packet_detail(packet_id)
                if detail:
                    result["detail"] = detail
            except Exception as e:
                result["error"] = str(e)

        def apply_result() -> None:
            if token != self._packet_detail_query_token:
                return
            if not self.packet_tree.exists(selected[0]):
                return
            latest = self.packet_tree.selection()
            if not latest:
                return
            latest_id = self._packet_tree_db_id(latest[0])
            if latest_id != packet_id:
                return
            detail = result.get("detail")
            if not detail:
                err = str(result.get("error", "")).strip()
                self.packet_detail_text.configure(state=tk.NORMAL)
                self.packet_detail_text.delete("1.0", tk.END)
                self.packet_detail_text.insert("1.0", err if err else "未获取到详情。")
                self.packet_detail_text.configure(state=tk.DISABLED)
                return
            self._put_cached_packet_detail(packet_id, detail)
            latest_values = self.packet_tree.item(latest[0], "values")
            self._render_packet_detail(detail, latest_values)

        self._packet_detail_query_thread = threading.Thread(
            target=lambda: (worker(), self.root.after(0, apply_result)),
            daemon=True,
        )
        self._packet_detail_query_thread.start()

    def _format_hex_dump(self, raw_hex: str) -> str:
        text = (raw_hex or "").strip()
        if not text:
            return "(empty)"
        out: list[str] = []
        byte_index = 0
        for i in range(0, len(text), 32):
            chunk = text[i : i + 32]
            pairs = [chunk[j : j + 2] for j in range(0, len(chunk), 2)]
            out.append(f"{byte_index:08X}  {' '.join(pairs)}")
            byte_index += len(pairs)
        return "\n".join(out)

    def _open_export_dialog(self, rows: list[dict]) -> None:
        dlg = tk.Toplevel(self.root)
        dlg.title("导出捕获流量")
        dlg.geometry("360x180")
        fmt_var = tk.StringVar(value="pcap")
        ttk.Label(dlg, text="导出格式", style="Hint.TLabel").pack(pady=(24, 8))
        ttk.Combobox(dlg, textvariable=fmt_var, values=["pcap", "csv", "json"], state="readonly", width=20).pack()

        def do_export() -> None:
            fmt = fmt_var.get().strip().lower()
            ext = f".{fmt}"
            output = filedialog.asksaveasfilename(
                title="保存流量文件",
                defaultextension=ext,
                filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")],
            )
            if not output:
                return
            out_path = self.runtime.export_packets(rows, Path(output), fmt)
            self.runtime.audit.log(self.username, "packet_export", str(out_path), f"format={fmt},count={len(rows)}")
            messagebox.showinfo("OK", f"导出成功:\n{out_path}")
            dlg.destroy()

        ttk.Button(dlg, text="[EXEC] 导出", style="Primary.TButton", command=do_export).pack(pady=20)

    def _refresh_interfaces(self) -> None:
        self.interfaces = self.runtime.capture.list_interfaces()
        names = [i["display_name"] for i in self.interfaces]
        self.iface_box["values"] = names
        if names:
            self.iface_box.current(0)

    def _refresh_environment_summary(self) -> None:
        env = self.runtime.get_environment_summary()
        txt = (
            f"[SYS] PyDivert状态：{'已就绪' if env['pydivert_ok'] else '未检测到'}  |  "
            f"网卡数量：{env['interface_count']}  |  "
            f"虚拟网卡：{env['vm_interface_count']}  |  "
            f"主机IP：{env['host_ip'] or '未知'}"
        )
        self.env_var.set(txt)
        if env["pydivert_ok"] and env["interface_count"] > 0:
            self.env_label.configure(style="EnvOk.TLabel")
        else:
            self.env_label.configure(style="EnvWarn.TLabel")

    def start_capture(self) -> None:
        if not self._require_admin():
            return
        interface = self._selected_interface_name()
        if not interface:
            return
        mode = self.mode_var.get()
        self.runtime.start_capture(interface, self.outbound_var.get())
        self.runtime.start_learning(mode)
        self.runtime.audit.log(self.username, "capture_start", interface, f"mode={mode}")

    def stop_capture(self) -> None:
        if not self._require_admin():
            return
        self.runtime.stop_capture()
        self.runtime.audit.log(self.username, "capture_stop", "-", "desktop")

    def generate_security_report(self) -> None:
        if not self._require_admin():
            return
        report_path = self.runtime.generate_security_report(self.username or "admin")
        webbrowser.open(report_path.resolve().as_uri())
        messagebox.showinfo("OK", f"Report generated:\n{report_path}")

    def _selected_interface_name(self) -> str | None:
        idx = self.iface_box.current()
        if idx < 0 or idx >= len(self.interfaces):
            messagebox.showwarning("ERR_INPUT", "Select interface first.")
            return None
        return str(self.interfaces[idx]["name"])

    def enable_interface(self) -> None:
        if not self._require_admin():
            return
        interface = self._selected_interface_name()
        if not interface:
            return
        ok, msg = self.runtime.set_interface_enabled(interface, True)
        if ok:
            self.runtime.audit.log(self.username, "interface_enable", interface, "desktop")
            self._refresh_interfaces()
            self._refresh_environment_summary()
            messagebox.showinfo("OK", "网卡已启用")
            return
        messagebox.showerror("ERR_NET", msg)

    def disable_interface(self) -> None:
        if not self._require_admin():
            return
        interface = self._selected_interface_name()
        if not interface:
            return
        self.runtime.stop_capture()
        ok, msg = self.runtime.set_interface_enabled(interface, False)
        if ok:
            self.runtime.audit.log(self.username, "interface_disable", interface, "desktop")
            self._refresh_interfaces()
            self._refresh_environment_summary()
            messagebox.showinfo("OK", "网卡已停用")
            return
        messagebox.showerror("ERR_NET", msg)

    def load_alerts(self) -> None:
        if not self.is_authenticated:
            return
        rows = self.runtime.query_alerts(
            limit=150,
            level=self.filter_level_var.get(),
            ip=self.filter_ip_var.get().strip(),
            process_name=self.filter_process_var.get().strip(),
            source="live",
        )
        for i in self.alert_tree.get_children():
            self.alert_tree.delete(i)
        for idx, r in enumerate(rows):
            parity = "even" if idx % 2 == 0 else "odd"
            level = str(r["level"]).lower()
            level_tag = "lvl_high" if level == "high" else ("lvl_medium" if level == "medium" else "")
            tags = tuple([parity] + ([level_tag] if level_tag else []))
            self.alert_tree.insert(
                "",
                tk.END,
                values=(
                    r["ts"],
                    r["src_ip"],
                    r["dst_ip"],
                    r.get("process_name", ""),
                    r["level"],
                    r.get("attack_type", ""),
                    r["sub_category"],
                    r["reason"],
                ),
                tags=tags,
            )
        self._refresh_attack_stats_panel()

    def _refresh_attack_stats_panel(self) -> None:
        stats = self.runtime.get_attack_stats(limit=10, source="live")
        lines = ["攻击统计 TOP10:"]
        for row in stats:
            lines.append(f"- {row.get('sub_category', '')}: {row.get('cnt', 0)}")
        if len(lines) == 1:
            lines.append("- 暂无数据")
        self.attack_stats_text.configure(state=tk.NORMAL)
        self.attack_stats_text.delete("1.0", tk.END)
        self.attack_stats_text.insert("1.0", "\n".join(lines))
        self.attack_stats_text.configure(state=tk.DISABLED)

    def _on_alert_select(self, _event=None) -> None:
        selected = self.alert_tree.selection()
        if not selected:
            return
        values = self.alert_tree.item(selected[0], "values")
        lines = [
            f"时间: {values[0]}",
            f"源: {values[1]} -> 目标: {values[2]}",
            f"进程: {values[3]}",
            f"等级: {values[4]}",
            f"攻击类型: {values[5]}",
            f"子类: {values[6]}",
            f"原因: {values[7]}",
        ]
        rows = self.runtime.query_alerts(limit=200, ip=str(values[1]), source="live")
        desc = ""
        miti = ""
        for row in rows:
            if str(row.get("ts", "")) == str(values[0]) and str(row.get("sub_category", "")) == str(values[6]):
                desc = str(row.get("attack_desc", ""))
                miti = str(row.get("mitigation", ""))
                break
        if desc:
            lines.append(f"说明: {desc}")
        if miti:
            lines.append(f"处置建议: {miti}")
        self.attack_desc_text.configure(state=tk.NORMAL)
        self.attack_desc_text.delete("1.0", tk.END)
        self.attack_desc_text.insert("1.0", "\n".join(lines))
        self.attack_desc_text.configure(state=tk.DISABLED)

    def reset_traffic_display(self) -> None:
        if not self._require_admin():
            return
        self._cancel_packet_render()
        self._packet_load_token += 1
        deleted_packets, deleted_alerts = self.runtime.clear_offline_analysis_data()
        self._packet_rows_in_view = []
        self._packet_tree_id_map.clear()
        self.packet_filter_source_var.set("offline")
        self.packet_progress_var.set(0.0)
        self.packet_import_status_var.set("离线分析状态: 空闲")
        for i in self.packet_tree.get_children():
            self.packet_tree.delete(i)
        self.packet_detail_text.configure(state=tk.NORMAL)
        self.packet_detail_text.delete("1.0", tk.END)
        self.packet_detail_text.insert("1.0", "选择一条流量记录可查看分层详情与原始字节。")
        self.packet_detail_text.configure(state=tk.DISABLED)
        self.packet_expert_text.configure(state=tk.NORMAL)
        self.packet_expert_text.delete("1.0", tk.END)
        self.packet_expert_text.insert("1.0", "Expert Info:\n- 选择一条流量记录后显示分析结论。")
        self.packet_expert_text.configure(state=tk.DISABLED)
        self._current_packet_detail = None
        for i in self.packet_detail_tree.get_children():
            self.packet_detail_tree.delete(i)
        self.runtime.audit.log(self.username, "offline_view_reset", "-", f"deleted_packets={deleted_packets},deleted_alerts={deleted_alerts}")

    def reset_realtime_display(self) -> None:
        if not self._require_admin():
            return
        deleted_packets, deleted_alerts = self.runtime.clear_realtime_monitor_data()
        for i in self.alert_tree.get_children():
            self.alert_tree.delete(i)
        self.attack_desc_text.configure(state=tk.NORMAL)
        self.attack_desc_text.delete("1.0", tk.END)
        self.attack_desc_text.insert("1.0", "选择告警可查看攻击类型说明与处置建议。")
        self.attack_desc_text.configure(state=tk.DISABLED)
        self.attack_stats_text.configure(state=tk.NORMAL)
        self.attack_stats_text.delete("1.0", tk.END)
        self.attack_stats_text.insert("1.0", "攻击统计将在加载告警后显示。")
        self.attack_stats_text.configure(state=tk.DISABLED)
        if self._alert_anim_job:
            self.root.after_cancel(self._alert_anim_job)
            self._alert_anim_job = None
        self._alert_target_value = "0"
        self.kpi_total.set("0")
        self.kpi_alerts.set("0")
        self.kpi_uptime.set("0s")
        self.kpi_sessions.set("0")
        self.kpi_privacy_blocks.set("0")
        self.kpi_alert_value_label.configure(style="KpiAlertValue.TLabel")
        self.runtime.audit.log(self.username, "realtime_view_reset", "-", f"deleted_packets={deleted_packets},deleted_alerts={deleted_alerts}")

    def block_selected_alert_ip(self) -> None:
        if not self._require_admin():
            return
        picked = self.alert_tree.selection()
        if not picked:
            messagebox.showwarning("ERR_INPUT", "Select alert first.")
            return
        values = self.alert_tree.item(picked[0], "values")
        src_ip = str(values[1]).strip()
        if not src_ip:
            messagebox.showwarning("ERR_INPUT", "Source IP is empty.")
            return
        if not messagebox.askyesno("CONFIRM", f"Block source IP {src_ip}?"):
            return
        ok, msg = self.runtime.block_ip_with_firewall(src_ip, self.username or "admin")
        if not ok:
            messagebox.showerror("ERR_NET", msg)
            return
        self.load_list_items()
        self.load_logs()
        messagebox.showinfo("OK", msg)

    def add_list_item(self) -> None:
        if not self._require_admin():
            return
        ip = self.list_ip_var.get().strip()
        if not ip:
            return
        self.runtime.list_service.upsert(ip, self.list_type_var.get(), 1, self.list_remark_var.get().strip())
        self.runtime.audit.log(self.username, "list_upsert", ip, self.list_type_var.get())
        self.list_ip_var.set("")
        self.list_remark_var.set("")
        self.load_list_items()

    def _get_selected_list(self) -> dict | None:
        picked = self.list_tree.selection()
        if not picked:
            return None
        values = self.list_tree.item(picked[0], "values")
        return {"id": int(values[0]), "enabled": int(values[3]), "remark": values[4]}

    def toggle_selected_list(self) -> None:
        if not self._require_admin():
            return
        item = self._get_selected_list()
        if not item:
            return
        self.runtime.list_service.update_item(item["id"], 0 if item["enabled"] == 1 else 1, item["remark"])
        self.runtime.audit.log(self.username, "list_update", str(item["id"]), "toggle")
        self.load_list_items()

    def delete_selected_list(self) -> None:
        if not self._require_admin():
            return
        item = self._get_selected_list()
        if not item:
            return
        self.runtime.list_service.delete(item["id"])
        self.runtime.audit.log(self.username, "list_delete", str(item["id"]), "desktop")
        self.load_list_items()

    def load_list_items(self) -> None:
        if not self.is_authenticated:
            return
        rows = self.runtime.list_service.all_items()
        for i in self.list_tree.get_children():
            self.list_tree.delete(i)
        for idx, r in enumerate(rows):
            parity = "even" if idx % 2 == 0 else "odd"
            self.list_tree.insert("", tk.END, values=(r["id"], r["ip"], r["list_type"], r["enabled"], r["remark"], r["updated_at"]), tags=(parity,))

    def _selected_log_id(self) -> int | None:
        picked = self.log_tree.selection()
        if not picked:
            return None
        values = self.log_tree.item(picked[0], "values")
        return int(values[0])

    def delete_selected_log(self) -> None:
        if not self._require_admin():
            return
        log_id = self._selected_log_id()
        if log_id is None:
            return
        self.runtime.audit.delete_log(log_id)
        self.runtime.audit.log(self.username, "log_delete", str(log_id), "desktop")
        self.load_logs()

    def delete_filtered_logs(self) -> None:
        if not self._require_admin():
            return
        keyword = self.log_keyword_var.get().strip()
        deleted = self.runtime.audit.delete_logs(keyword=keyword)
        self.runtime.audit.log(self.username, "log_delete_batch", "-", f"deleted={deleted}")
        messagebox.showinfo("OK", f"Deleted {deleted} records.")
        self.load_logs()

    def load_logs(self) -> None:
        if not self.is_authenticated:
            return
        rows = self.runtime.audit.query(limit=180, keyword=self.log_keyword_var.get().strip())
        for i in self.log_tree.get_children():
            self.log_tree.delete(i)
        for idx, r in enumerate(rows):
            parity = "even" if idx % 2 == 0 else "odd"
            self.log_tree.insert("", tk.END, values=(r["id"], r["ts"], r["username"], r["action"], r["target"], r["detail"]), tags=(parity,))

    def _animate_alert_value(self, text: str, idx: int, danger: bool) -> None:
        self.kpi_alerts.set(text[:idx])
        self.kpi_alert_value_label.configure(style="KpiAlertDanger.TLabel" if danger else "KpiAlertValue.TLabel")
        if idx < len(text):
            self._alert_anim_job = self.root.after(10, self._animate_alert_value, text, idx + 1, danger)
        else:
            self._alert_anim_job = None

    def _set_alert_kpi(self, alerts: int) -> None:
        target = f"{alerts}"
        danger = alerts > 0
        if target == self._alert_target_value and self.kpi_alerts.get() == target:
            self.kpi_alert_value_label.configure(style="KpiAlertDanger.TLabel" if danger else "KpiAlertValue.TLabel")
            return
        self._alert_target_value = target
        if self._alert_anim_job:
            self.root.after_cancel(self._alert_anim_job)
            self._alert_anim_job = None
        self._animate_alert_value(target, 1, danger)

    def _tick(self) -> None:
        d = self.runtime.last_summary
        self.kpi_total.set(f"{d['total_packets']}")
        self._set_alert_kpi(int(d["alerts"]))
        self.kpi_uptime.set(f"{d['uptime_sec']}s")
        self.kpi_sessions.set(f"{d['active_sessions']}")
        self.kpi_privacy_blocks.set(f"{d.get('privacy_blocks', 0)}")
        ls = self.runtime.get_learning_status()
        if not self.runtime.is_capture_running():
            self.learning_var.set("STATUS: IDLE")
        elif ls["in_learning"]:
            self.learning_var.set(f"STATUS: LEARNING | REMAINING: {ls['remaining_seconds']}s")
        else:
            self.learning_var.set("STATUS: MONITORING")
        self.root.after(1500, self._tick)

    def run(self) -> None:
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)
        self.root.mainloop()

    def _on_close(self) -> None:
        self.runtime.stop_capture()
        self.runtime.db.close()
        self.root.destroy()


def main() -> None:
    app = DesktopApp()
    app.run()


if __name__ == "__main__":
    main()
