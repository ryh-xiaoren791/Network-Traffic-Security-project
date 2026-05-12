import tkinter as tk
import tkinter.font as tkfont
import webbrowser
import threading
import base64
import ipaddress
import traceback
from pathlib import Path
from tkinter import filedialog, ttk, messagebox

from src.app.packet_batch_exports import (
    build_batch_export_audit_detail,
    build_batch_export_status,
    build_batch_export_status_done,
    build_batch_export_success_message,
    execute_packet_batch_export,
    export_action_formats,
    export_action_hint,
)
from src.app.runtime import AppRuntime
from src.config import CONFIG
from src.core.auth.service import AuthService
from src.core.ctf import build_packet_ctf_clues
from src.core.flow_view_models import (
    FLOW_ARTIFACT_LABEL_MAP,
    FLOW_DIRECTION_LABEL_MAP,
    STREAM_MODE_OPTIONS,
    artifact_formats,
    asset_detail_text,
    asset_tree_values,
    build_flow_analysis_tip,
    build_flow_window_title,
    candidate_detail_text,
    candidate_tree_values,
    object_detail_text,
    object_export_suffix,
    object_tree_values,
)
from src.core.frame_intel import build_frame_ctf_clues, extract_frame_intel
from src.core.packet_detail_view import (
    PACKET_DETAIL_MODE_OPTIONS,
    build_expert_info_text,
    build_packet_detail_tree_nodes,
    build_packet_position_text,
)
from src.core.packet_inspection import decode_raw_bytes, dissect_packet_bytes, extract_app_fields, extract_ascii, extract_http_line

CTF_MAX_PACKET_CLUES = 2000
CTF_MAX_FRAME_CLUES = 200
CTF_LARGE_PAYLOAD_BYTES = 1200
CTF_DETAIL_INTERESTING_PORTS = {53, 80, 443, 445, 502, 3389, 8443, 9001}
PACKET_APP_HINT_PORTS = (
    ({80, 8080, 8000}, "HTTP?"),
    ({443, 8443}, "TLS?"),
    ({53}, "DNS?"),
)
PLAINTEXT_RISK_PORTS = {21, 23, 110, 143}
EXPERT_SENSITIVE_KEYWORDS = ["password", "passwd", "token", "authorization", "union select", "cmd=", "powershell"]
DEFAULT_PACKET_PANEL_TEXTS = {
    "packet_summary": "流量摘要:\n- 选择一条记录后，先给出人话结论，再继续看协议树和原始数据。",
    "packet_expert": "Expert Info:\n- 选择一条流量记录后显示分析结论。",
    "packet_detail": "选择一条流量记录可查看分层详情与原始字节。",
    "session_summary": "会话视图将汇总当前筛选结果中的连接，适合新手先看“谁在和谁通信”。",
    "frame_summary": "通用帧视图会保留离线文件里的所有帧，即使当前还无法解析成 IP/TCP/UDP，也能先看链路类型、长度和原始字节。",
    "frame_detail": "选择一条原始帧后可查看原始字节。",
    "ctf_clue": "实战线索会优先把高风险、明文、异常端口、外联等流量挑出来，方便 CTF 或取证时快速缩小范围。",
}
DEFAULT_ALERT_PANEL_TEXTS = {
    "attack_desc": "选择告警可查看攻击类型说明与处置建议。",
    "attack_stats": "攻击统计将在加载告警后显示。",
}


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
        self._packet_query_result: dict[str, object] = {"rows": [], "total": 0, "page": 1, "page_size": 500, "total_pages": 1}
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
        self._packet_flow_query_token = 0
        self._packet_detail_cache: dict[int, dict] = {}
        self._packet_detail_cache_order: list[int] = []
        self._packet_detail_cache_max = 2000
        self._packet_time_base = 0.0
        self._current_packet_detail: dict | None = None
        self._packet_rows_in_view: list[dict] = []
        self._packet_tree_id_map: dict[str, int] = {}
        self._session_rows_in_view: list[dict] = []
        self._session_tree_id_map: dict[str, int] = {}
        self._ctf_clue_rows_in_view: list[dict] = []
        self._ctf_clue_tree_id_map: dict[str, int] = {}
        self._admin_only_controls: list[tk.Widget] = []
        self._packet_page = 1
        self._packet_total_pages = 1
        self._packet_total_rows = 0
        self._nav_width_expanded = 190
        self._traffic_tools_expanded = False
        self.root = tk.Tk()
        self.root.title("网络流量安全监测与分析平台 个人版")
        self.root.geometry("1380x900")
        self.root.minsize(1220, 760)
        self.root.configure(background="#F5F7FA")
        self.root.report_callback_exception = self._handle_ui_exception

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
        style.configure("Grip.TSizegrip", background=BG)
        
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

        box = ttk.LabelFrame(self.login_frame, text="[AUTH] 登录", style="Card.TLabelframe")
        box.place(relx=0.5, rely=0.22, anchor=tk.N, width=420, height=310)
        content = ttk.Frame(box, style="TFrame")
        content.pack(fill=tk.BOTH, expand=True, padx=32, pady=(32, 24))
        
        ttk.Label(content, text="AI_TRAFFIC_MONITOR", style="Title.TLabel", anchor=tk.CENTER).pack(fill=tk.X, pady=(0, 6))
        ttk.Label(content, text="统一身份认证", style="Hint.TLabel", anchor=tk.CENTER).pack(fill=tk.X, pady=(0, 24))

        self.login_user_var = tk.StringVar()
        self.login_pass_var = tk.StringVar()
        
        row1 = ttk.Frame(content)
        row1.pack(fill=tk.X, pady=(0, 14))
        self.login_user_entry = self._pack_labeled_entry(
            row1,
            "[ID]  用户",
            self.login_user_var,
            label_width=11,
            entry_padx=(8, 0),
            fill=tk.X,
            expand=True,
        )
        
        row2 = ttk.Frame(content)
        row2.pack(fill=tk.X, pady=(0, 20))
        self.login_pass_entry = self._pack_labeled_entry(
            row2,
            "[KEY] 密码",
            self.login_pass_var,
            show="*",
            label_width=11,
            entry_padx=(8, 0),
            fill=tk.X,
            expand=True,
        )
        self.login_user_entry.bind("<Return>", lambda _event: self.login())
        self.login_pass_entry.bind("<Return>", lambda _event: self.login())
        
        btns = ttk.Frame(content)
        btns.pack(fill=tk.X, pady=(12, 0))
        ttk.Button(btns, text="[EXEC] 登录", style="Primary.TButton", command=self.login).pack(fill=tk.X, ipady=4)

    def _build_main_view(self) -> None:
        self.main_frame = tk.Frame(self.root, bg="#F5F7FA")
        
        self.main_canvas = tk.Canvas(self.main_frame, bg="#F5F7FA", highlightthickness=0)
        self.main_canvas.place(x=0, y=0, relwidth=1, relheight=1)
        self.main_canvas.bind("<Configure>", lambda e: self._draw_grid(self.main_canvas, e.width, e.height))

        # Inner frame to hold content over canvas, allowing grid to show at borders
        content = tk.Frame(self.main_frame, bg="#F5F7FA")
        content.pack(fill=tk.BOTH, expand=True, padx=14, pady=10)

        top = ttk.Frame(content, style="Top.TFrame")
        top.pack(fill=tk.X, pady=(0, 4))
        self.top_status_var = tk.StringVar(value="[STATUS: UNAUTH]")
        self.nav_panel = ttk.Frame(top, style="Top.TFrame")
        self.nav_panel.pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(top, text="[EXIT] 退出登录", style="Danger.TButton", command=self.logout).pack(side=tk.RIGHT, padx=2, pady=2)
        body = ttk.Frame(content, style="TFrame")
        body.pack(fill=tk.BOTH, expand=True, pady=(0, 2))

        self.page_container = ttk.Frame(body, style="TFrame")
        self.page_container.pack(fill=tk.BOTH, expand=True)

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
            btn.pack(side=tk.LEFT, padx=(0, 8), pady=2)
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
        self.login_user_var.set("")
        self.login_pass_var.set("")
        self.root.after(0, self.login_user_entry.focus_set)

    def _show_main(self) -> None:
        self.login_frame.pack_forget()
        self.main_frame.pack(fill=tk.BOTH, expand=True)
        self.root.after(80, self._apply_default_layout)

    def _apply_default_layout(self) -> None:
        self.root.update_idletasks()
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
        self.packet_filter_process_var = tk.StringVar()
        self.packet_filter_ip_var = tk.StringVar()
        self.packet_filter_source_var = tk.StringVar(value="offline")
        self.packet_rule_expr_var = tk.StringVar()
        self.packet_only_abnormal_var = tk.BooleanVar(value=False)
        self.offline_mode_var = tk.StringVar(value="balanced")
        self.packet_import_status_var = tk.StringVar(value="离线分析状态: 空闲")
        self.packet_sort_key_var = tk.StringVar(value="ts")
        self.packet_sort_desc_var = tk.BooleanVar(value=True)
        self.packet_page_size_var = tk.StringVar(value="500")
        self.packet_page_info_var = tk.StringVar(value="页 1/1 | 0 条")
        self.traffic_tools_toggle_var = tk.StringVar(value="[MORE] 展开高级操作")
        toolbar = ttk.Frame(self.page_traffic)
        toolbar.pack(fill=tk.X, pady=(0, 3))
        query_box = ttk.LabelFrame(toolbar, text="[QUERY] 查询与分页", style="Card.TLabelframe")
        query_box.pack(fill=tk.X, pady=(0, 3))
        query_box.columnconfigure(10, weight=1)
        ttk.Label(query_box, text="[PROC]:", style="Hint.TLabel").grid(row=0, column=0, padx=(8, 4), pady=(5, 2), sticky="w")
        process_entry = ttk.Entry(query_box, textvariable=self.packet_filter_process_var, width=14)
        process_entry.grid(row=0, column=1, padx=(0, 8), pady=(5, 2), sticky="w")
        ttk.Label(query_box, text="[IP]:", style="Hint.TLabel").grid(row=0, column=2, padx=(0, 4), pady=(5, 2), sticky="w")
        ip_entry = ttk.Entry(query_box, textvariable=self.packet_filter_ip_var, width=14)
        ip_entry.grid(row=0, column=3, padx=(0, 8), pady=(5, 2), sticky="w")
        ttk.Label(query_box, text="[SRC]:", style="Hint.TLabel").grid(row=0, column=4, padx=(0, 4), pady=(5, 2), sticky="w")
        source_box = ttk.Combobox(
            query_box,
            textvariable=self.packet_filter_source_var,
            values=["offline", "live"],
            width=8,
            state="readonly",
        )
        source_box.grid(row=0, column=5, padx=(0, 8), pady=(5, 2), sticky="w")
        ttk.Checkbutton(query_box, text="[ABN] 仅异常关联", variable=self.packet_only_abnormal_var).grid(
            row=0,
            column=6,
            padx=(0, 8),
            pady=(5, 2),
            sticky="w",
        )
        ttk.Label(query_box, text="[SORT]:", style="Hint.TLabel").grid(row=0, column=7, padx=(0, 4), pady=(5, 2), sticky="w")
        ttk.Combobox(
            query_box,
            textvariable=self.packet_sort_key_var,
            values=["ts", "id", "risk_level", "process_name", "src_ip", "dst_ip", "src_port", "dst_port", "proto", "length", "source"],
            width=10,
            state="readonly",
        ).grid(row=0, column=8, padx=(0, 8), pady=(5, 2), sticky="w")
        ttk.Button(query_box, text="[ORDER] 升降", style="Secondary.TButton", command=self._toggle_packet_sort_order).grid(
            row=1,
            column=7,
            padx=(0, 8),
            pady=(0, 5),
            sticky="w",
        )
        ttk.Button(query_box, text="[CMD] 查询", style="Primary.TButton", command=self.load_packets).grid(
            row=1,
            column=8,
            padx=(0, 8),
            pady=(0, 5),
            sticky="w",
        )
        ttk.Label(query_box, text="[RULE]:", style="Hint.TLabel").grid(row=1, column=0, padx=(8, 4), pady=(0, 5), sticky="w")
        rule_entry = ttk.Entry(query_box, textvariable=self.packet_rule_expr_var, width=42)
        rule_entry.grid(row=1, column=1, columnspan=6, padx=(0, 8), pady=(0, 5), sticky="w")
        ttk.Label(query_box, text="[SIZE]:", style="Hint.TLabel").grid(row=0, column=9, padx=(0, 4), pady=(5, 2), sticky="w")
        packet_page_size_box = ttk.Combobox(
            query_box,
            textvariable=self.packet_page_size_var,
            values=["200", "500", "1000", "2000"],
            width=6,
            state="readonly",
        )
        packet_page_size_box.grid(row=0, column=10, padx=(0, 8), pady=(5, 2), sticky="w")
        packet_page_size_box.bind("<<ComboboxSelected>>", lambda _event: self.load_packets())
        ttk.Button(query_box, text="[PREV] 上一页", style="Secondary.TButton", command=self._load_prev_packet_page).grid(
            row=1,
            column=9,
            padx=(0, 6),
            pady=(0, 5),
            sticky="w",
        )
        ttk.Button(query_box, text="[NEXT] 下一页", style="Secondary.TButton", command=self._load_next_packet_page).grid(
            row=1,
            column=10,
            padx=(0, 8),
            pady=(0, 5),
            sticky="w",
        )
        ttk.Label(query_box, textvariable=self.packet_page_info_var, style="Path.TLabel").grid(
            row=0,
            column=11,
            padx=(0, 8),
            pady=(5, 2),
            sticky="w",
        )
        ops_box = ttk.LabelFrame(toolbar, text="[OPS] 常用操作", style="Card.TLabelframe")
        ops_box.pack(fill=tk.X, pady=(0, 3))
        ttk.Label(ops_box, text="[MODE]:", style="Hint.TLabel").grid(row=0, column=0, padx=(8, 4), pady=5, sticky="w")
        ttk.Combobox(
            ops_box,
            textvariable=self.offline_mode_var,
            values=["balanced", "extreme"],
            width=10,
            state="readonly",
        ).grid(row=0, column=1, padx=(0, 8), pady=5, sticky="w")
        traffic_import_btn = None
        for column, text, style, command, textvariable, sticky in (
            (2, "[FILE] 导入离线PCAP", "Secondary.TButton", self.import_offline_pcap, None, "w"),
            (3, "[FLOW] 跟踪会话", "Secondary.TButton", self.open_follow_stream_viewer, None, "w"),
            (5, "", "Secondary.TButton", self._toggle_traffic_tools_panel, self.traffic_tools_toggle_var, "e"),
        ):
            button = ttk.Button(ops_box, text=text, textvariable=textvariable, style=style, command=command)
            button.grid(row=0, column=column, padx=(0, 8), pady=5, sticky=sticky)
            if column == 2:
                traffic_import_btn = button
        ops_box.columnconfigure(5, weight=1)

        self.traffic_tools_panel = ttk.LabelFrame(toolbar, text="[MORE] 高级操作", style="Card.TLabelframe")
        traffic_report_btn = traffic_reset_btn = traffic_batch_export_btn = None
        for column, text, style, command, padx in (
            (0, "[RPT] 生成分析报告", "Secondary.TButton", self.generate_traffic_report, (8, 8)),
            (1, "[RESET] 重置显示窗口", "Danger.TButton", self.reset_traffic_display, (0, 8)),
            (2, "[SAVE] 批量导出/提取", "Secondary.TButton", self.open_packet_batch_export_dialog, (0, 8)),
        ):
            button = ttk.Button(self.traffic_tools_panel, text=text, style=style, command=command)
            button.grid(row=0, column=column, padx=padx, pady=8, sticky="w")
            if column == 0:
                traffic_report_btn = button
            elif column == 1:
                traffic_reset_btn = button
            else:
                traffic_batch_export_btn = button
        self._register_admin_only(traffic_report_btn, traffic_reset_btn, traffic_import_btn, traffic_batch_export_btn)
        self._set_traffic_tools_panel(expanded=False)
        for entry in (process_entry, ip_entry, rule_entry):
            entry.bind("<Return>", lambda _event: self.load_packets())
        source_box.bind("<<ComboboxSelected>>", lambda _event: self.load_packets())
        ttk.Label(
            self.page_traffic,
            text="规则示例: tcp && ip.src==10.0.0.2  |  udp && port==53  |  process contains chrome  |  !icmp && len>100",
            style="Hint.TLabel",
        ).pack(fill=tk.X, pady=(0, 4), anchor=tk.W)
        ttk.Label(self.page_traffic, textvariable=self.packet_import_status_var, style="Redline.TLabel").pack(fill=tk.X, pady=(0, 6), anchor=tk.W)
        self.packet_progress_var = tk.DoubleVar(value=0.0)
        self.traffic_workbench = ttk.Notebook(self.page_traffic)
        self.traffic_workbench.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        self.traffic_session_tab, session_left, session_right = self._create_workbench_two_panel_tab(
            self.traffic_workbench,
            title="会话",
            left_title="[SESSION] 当前筛选结果会话概览",
            right_title="[GUIDE] 会话摘要与操作建议",
        )
        session_left.rowconfigure(0, weight=1)
        session_left.columnconfigure(0, weight=1)
        self.session_tree = self._create_headings_tree(
            session_left,
            columns=[
                ("app", "[APP]", 100),
                ("direction", "[DIR]", 120),
                ("process", "[PROC]", 150),
                ("peer", "[PEER]", 180),
                ("packets", "[PKTS]", 80),
                ("bytes", "[BYTES]", 90),
                ("risk", "[RISK]", 90),
            ],
            height=18,
        )
        self.session_tree.bind("<<TreeviewSelect>>", self._on_session_select)
        self.session_tree.bind("<Double-1>", lambda _event: self._open_selected_session_flow())

        session_right.columnconfigure(0, weight=1)
        session_right.rowconfigure(0, weight=1)
        self.session_summary_text = self._grid_text_view(session_right, row=0, padx=6, pady=(6, 4))
        self._set_text_content(self.session_summary_text, "会话视图将汇总当前筛选结果中的连接，适合新手先看“谁在和谁通信”。")
        session_ops = ttk.Frame(session_right)
        session_ops.grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 6))
        self._pack_toolbar_button(session_ops, "[FLOW] 打开会话追踪", command=self._open_selected_session_flow, padx=(0, 0))
        self._pack_toolbar_button(session_ops, "[PACKET] 定位到数据包", command=self._focus_selected_session_packet, padx=(6, 0))

        self.traffic_frame_tab, frame_left, frame_right = self._create_workbench_two_panel_tab(
            self.traffic_workbench,
            title="通用帧",
            left_title="[FRAME] 原始抓包帧",
            right_title="[DETAIL] 帧摘要与原始内容",
        )
        frame_left.rowconfigure(0, weight=1)
        frame_left.columnconfigure(0, weight=1)
        self.frame_tree = self._create_headings_tree(
            frame_left,
            columns=[
                ("frame_no", "[NO]", 70),
                ("ts", "[TS]", 150),
                ("linktype", "[LINKTYPE]", 90),
                ("iface", "[IFACE]", 150),
                ("frame_type", "[TYPE]", 110),
                ("wirelen", "[LEN]", 90),
                ("summary", "[SUMMARY]", 360),
            ],
            height=18,
        )
        self.frame_tree.bind("<<TreeviewSelect>>", self._on_frame_select)

        frame_right.columnconfigure(0, weight=1)
        frame_right.rowconfigure(2, weight=1)
        self.frame_summary_text = self._grid_text_view(frame_right, row=0, height=8, padx=6, pady=(6, 4))
        self._set_text_content(self.frame_summary_text, "通用帧视图会保留离线文件里的所有帧，即使当前还无法解析成 IP/TCP/UDP，也能先看链路类型、长度和原始字节。")
        frame_bar = ttk.Frame(frame_right)
        frame_bar.grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 2))
        self.frame_raw_mode_var = tk.StringVar(value="hex")
        self._pack_labeled_combobox(frame_bar, "[RAW] 编码", self.frame_raw_mode_var, list(PACKET_DETAIL_MODE_OPTIONS), width=12)
        self.frame_detail_text = self._grid_scrollable_text_view(frame_right, row=2, wrap=tk.NONE, padx=6, pady=(0, 6))
        self._set_text_content(self.frame_detail_text, "选择一条原始帧后可查看原始字节。")
        self.frame_raw_mode_var.trace_add("write", lambda *_: self._render_current_frame_raw())
        self._frame_tree_id_map = {}
        self._frame_rows_in_view = []
        self._current_frame_detail = None

        self.traffic_packet_tab = ttk.Frame(self.traffic_workbench, padding=(0, 2, 0, 0))
        self.traffic_workbench.add(self.traffic_packet_tab, text="数据包")
        self.traffic_split = tk.PanedWindow(self.traffic_packet_tab, orient=tk.VERTICAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        self.traffic_split.pack(fill=tk.BOTH, expand=True, pady=(0, 6))
        packet_table = ttk.Frame(self.traffic_split)
        self.packet_tree = ttk.Treeview(
            packet_table,
            columns=("no", "delta", "ts", "source", "risk_level", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "length", "info"),
            show="headings",
            height=23,
        )
        for name, heading, width in [
            ("no", "[NO]", 70),
            ("delta", "[DELTA]", 90),
            ("ts", "[TS]", 150),
            ("source", "[SOURCE]", 80),
            ("risk_level", "[RISK_LEVEL]", 90),
            ("src_ip", "[SRC_IP]", 130),
            ("src_port", "[SRC_PORT]", 85),
            ("dst_ip", "[DST_IP]", 130),
            ("dst_port", "[DST_PORT]", 85),
            ("proto", "[PROTO]", 90),
            ("length", "[LENGTH]", 90),
            ("info", "[INFO]", 520),
        ]:
            self.packet_tree.heading(name, text=heading, command=lambda col=name: self._on_packet_heading_sort(col))
            self.packet_tree.column(name, width=width, anchor=tk.W)
        packet_table.columnconfigure(0, weight=1)
        packet_table.rowconfigure(0, weight=1)
        self.packet_tree_y_scroll = self._create_scrollbar(packet_table, orient=tk.VERTICAL, command=self._on_packet_tree_yview)
        packet_tree_x_scroll = self._create_scrollbar(packet_table, orient=tk.HORIZONTAL, command=self.packet_tree.xview)
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
        self.packet_detail_tree = self._create_field_value_tree(left, field_width=260, value_width=380)
        paned.add(left, minsize=420)

        right = ttk.Frame(paned)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(2, weight=1)
        right.rowconfigure(3, weight=3)
        self.packet_raw_mode_var = tk.StringVar(value="hex")
        self.packet_summary_text = self._grid_text_view(right, row=0, height=5, bg="#F0F4F8", pady=(4, 4))
        self._set_text_content(self.packet_summary_text, "流量摘要:\n- 选择一条记录后，先给出人话结论，再继续看协议树和原始数据。")
        raw_bar = ttk.Frame(right)
        raw_bar.grid(row=1, column=0, sticky="ew", padx=4, pady=(0, 2))
        self._pack_labeled_combobox(raw_bar, "[RAW] 编码", self.packet_raw_mode_var, list(PACKET_DETAIL_MODE_OPTIONS), width=12)
        self._pack_toolbar_button(raw_bar, "[POP] 详情弹窗", command=self.open_packet_detail_dialog, side=tk.RIGHT, padx=0)
        self.packet_expert_text = self._grid_text_view(right, row=2, height=4)
        self._set_text_content(self.packet_expert_text, "Expert Info:\n- 选择一条流量记录后显示分析结论。")
        self.packet_detail_text = self._grid_scrollable_text_view(right, row=3, height=10, wrap=tk.NONE)
        self._set_text_content(self.packet_detail_text, "选择一条流量记录可查看分层详情与原始字节。")
        self.packet_raw_mode_var.trace_add("write", lambda *_: self._render_current_packet_raw())
        paned.add(right, minsize=460)

        self.traffic_ctf_tab, ctf_left, ctf_right = self._create_workbench_two_panel_tab(
            self.traffic_workbench,
            title="实战线索",
            left_title="[CLUE] CTF / 取证线索",
            right_title="[DETAIL] 线索解读与下一步动作",
        )
        ctf_left.rowconfigure(0, weight=1)
        ctf_left.columnconfigure(0, weight=1)
        self.ctf_clue_tree = self._create_headings_tree(
            ctf_left,
            columns=[
                ("level", "[LVL]", 80),
                ("type", "[TYPE]", 110),
                ("summary", "[SUMMARY]", 340),
                ("filter", "[FILTER]", 220),
            ],
            height=18,
        )
        self.ctf_clue_tree.bind("<<TreeviewSelect>>", self._on_ctf_clue_select)
        self.ctf_clue_tree.bind("<Double-1>", lambda _event: self._apply_selected_ctf_filter())

        ctf_right.columnconfigure(0, weight=1)
        ctf_right.rowconfigure(0, weight=1)
        self.ctf_clue_text = self._grid_text_view(ctf_right, row=0, padx=6, pady=(6, 4))
        self._set_text_content(self.ctf_clue_text, "实战线索会优先把高风险、明文、异常端口、外联等流量挑出来，方便 CTF 或取证时快速缩小范围。")
        ctf_ops = ttk.Frame(ctf_right)
        ctf_ops.grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 6))
        self._pack_toolbar_button(ctf_ops, "[APPLY] 应用线索过滤", command=self._apply_selected_ctf_filter, padx=(0, 0))
        self._pack_toolbar_button(ctf_ops, "[PACKET] 跳转数据包", command=self._jump_to_ctf_packet, padx=(6, 0))

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
        realtime_start_btn = realtime_stop_btn = realtime_enable_btn = realtime_disable_btn = realtime_report_btn = None
        for row, column, text, style, command, padx, pady, sticky in (
            (0, 3, "[RUN] 开始采集", "Primary.TButton", self.start_capture, 6, 8, ""),
            (0, 4, "[HALT] 停止采集", "Danger.TButton", self.stop_capture, 6, 8, ""),
            (1, 0, "[SYNC] 刷新网卡", "Secondary.TButton", self._refresh_interfaces, 8, (0, 8), "w"),
            (1, 1, "[NIC+] 启用网卡", "Secondary.TButton", self.enable_interface, 8, (0, 8), "w"),
            (1, 2, "[NIC-] 停用网卡", "Danger.TButton", self.disable_interface, 8, (0, 8), "w"),
            (1, 3, "[RPT] 生成分析报告", "Secondary.TButton", self.generate_realtime_report, 8, (0, 8), "w"),
        ):
            button = ttk.Button(toolbar, text=text, style=style, command=command)
            grid_kwargs = {"row": row, "column": column, "padx": padx, "pady": pady}
            if sticky:
                grid_kwargs["sticky"] = sticky
            button.grid(**grid_kwargs)
            if (row, column) == (0, 3):
                realtime_start_btn = button
            elif (row, column) == (0, 4):
                realtime_stop_btn = button
            elif (row, column) == (1, 1):
                realtime_enable_btn = button
            elif (row, column) == (1, 2):
                realtime_disable_btn = button
            elif (row, column) == (1, 3):
                realtime_report_btn = button
        self._register_admin_only(
            realtime_start_btn,
            realtime_stop_btn,
            realtime_enable_btn,
            realtime_disable_btn,
            realtime_report_btn,
        )
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
        self._create_kpi_card(kpi, column=0, title="[MEASURE] 总流量包数", value_var=self.kpi_total)
        self.kpi_alert_value_label = self._create_kpi_card(
            kpi,
            column=1,
            title="[MEASURE] 当前告警数",
            value_var=self.kpi_alerts,
            value_style="KpiAlertValue.TLabel",
            value_pady=(4, 0),
        )
        self._create_kpi_card(kpi, column=2, title="[MEASURE] 在线时长", value_var=self.kpi_uptime)
        self._create_kpi_card(kpi, column=3, title="[MEASURE] 活动会话", value_var=self.kpi_sessions)
        self._create_kpi_card(kpi, column=4, title="[MEASURE] 隐私追踪拦截", value_var=self.kpi_privacy_blocks)
        bar = ttk.Frame(self.page_realtime)
        bar.pack(fill=tk.X, pady=6)
        self.filter_process_var = tk.StringVar()
        self.filter_ip_var = tk.StringVar()
        self.filter_level_var = tk.StringVar(value="")
        self._pack_labeled_entry(bar, "[PROC]:", self.filter_process_var, width=18)
        self._pack_labeled_entry(bar, "[IP]:", self.filter_ip_var, width=18)
        self._pack_labeled_combobox(bar, "[LVL]:", self.filter_level_var, ["", "high", "medium", "low"], width=12)
        self._pack_toolbar_button(bar, "[CMD] 查询告警", command=self.load_alerts)
        realtime_reset_btn = self._pack_toolbar_button(bar, "[RESET] 重置显示窗口", command=self.reset_realtime_display, style="Danger.TButton")
        realtime_block_btn = self._pack_toolbar_button(bar, "[BLOCK] 一键封禁源IP", command=self.block_selected_alert_ip, style="Danger.TButton")
        self._pack_toolbar_button(bar, "[VIEW] 告警详情弹窗", command=self.open_alert_detail_window)
        self._register_admin_only(realtime_reset_btn, realtime_block_btn)
        self.realtime_split = tk.PanedWindow(self.page_realtime, orient=tk.VERTICAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        self.realtime_split.pack(fill=tk.BOTH, expand=True)
        alert_table = ttk.Frame(self.realtime_split)
        self.alert_tree = self._create_headings_tree(
            alert_table,
            columns=[
                ("ts", "[TS]", 150),
                ("src_ip", "[SRC_IP]", 120),
                ("dst_ip", "[DST_IP]", 120),
                ("process_name", "[PROCESS_NAME]", 130),
                ("level", "[LEVEL]", 70),
                ("attack_type", "[ATTACK_TYPE]", 130),
                ("sub_category", "[SUB_CATEGORY]", 140),
                ("reason", "[REASON]", 430),
            ],
            height=23,
        )
        self.alert_tree.bind("<<TreeviewSelect>>", self._on_alert_select)
        panel = ttk.Frame(self.realtime_split)
        self.realtime_split.add(alert_table, minsize=260)
        self.realtime_split.add(panel, minsize=170)
        self.attack_desc_text = self._pack_text_view(panel, height=8, padx=(0, 6))
        self._set_text_content(self.attack_desc_text, "选择告警可查看攻击类型说明与处置建议。")
        self.attack_stats_text = self._pack_text_view(panel, side=tk.RIGHT, fill=tk.Y, expand=False, width=42, height=8, padx=0)
        self._set_text_content(self.attack_stats_text, "攻击统计将在加载告警后显示。")

    def open_alert_detail_window(self) -> None:
        desc = (self.attack_desc_text.get("1.0", tk.END).strip() if hasattr(self, "attack_desc_text") else "") or "选择告警可查看攻击类型说明与处置建议。"
        stats = (self.attack_stats_text.get("1.0", tk.END).strip() if hasattr(self, "attack_stats_text") else "") or "攻击统计将在加载告警后显示。"

        dlg = tk.Toplevel(self.root)
        self._prepare_detail_dialog(dlg, "告警详情", "1080x640", 860, 520)
        split = tk.PanedWindow(dlg, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        split.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        left = ttk.LabelFrame(split, text="[DETAIL] 攻击说明", style="Card.TLabelframe")
        right = ttk.LabelFrame(split, text="[STATS] 攻击统计", style="Card.TLabelframe")
        split.add(left, minsize=520)
        split.add(right, minsize=260)

        detail_text = self._pack_text_view(left)
        self._set_text_content(detail_text, desc)

        stats_text = self._pack_text_view(right)
        self._set_text_content(stats_text, stats)
        self._attach_dialog_sizegrip(dlg)

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
        self._pack_labeled_entry(bar1, "[IP]:", self.list_ip_var, width=20)
        self._pack_labeled_combobox(bar1, "[TYP]:", self.list_type_var, ["white", "black"], width=10)
        self._pack_labeled_entry(bar1, "[RMK]:", self.list_remark_var, width=24)
        list_add_btn = self._pack_toolbar_button(bar2, "[CMD] 新增", command=self.add_list_item, style="Primary.TButton")
        list_toggle_btn = self._pack_toolbar_button(bar2, "[CMD] 启停切换", command=self.toggle_selected_list)
        list_delete_btn = self._pack_toolbar_button(bar2, "[CMD] 删除", command=self.delete_selected_list, style="Danger.TButton")
        self._pack_toolbar_button(bar2, "[CMD] 刷新", command=self.load_list_items)
        self._register_admin_only(list_add_btn, list_toggle_btn, list_delete_btn)
        list_table = ttk.Frame(self.page_lists)
        list_table.pack(fill=tk.BOTH, expand=True)
        self.list_tree = self._create_headings_tree(
            list_table,
            columns=[
                ("id", "[ID]", 60),
                ("ip", "[IP]", 170),
                ("list_type", "[LIST_TYPE]", 90),
                ("enabled", "[ENABLED]", 80),
                ("remark", "[REMARK]", 300),
                ("updated_at", "[UPDATED_AT]", 220),
            ],
            height=23,
        )

    def _build_logs_tab(self) -> None:
        bar = ttk.Frame(self.page_logs)
        bar.pack(fill=tk.X, pady=6)
        bar1 = ttk.Frame(bar)
        bar1.pack(fill=tk.X, pady=(0, 4), anchor=tk.W)
        bar2 = ttk.Frame(bar)
        bar2.pack(fill=tk.X, anchor=tk.W)
        self.log_keyword_var = tk.StringVar()
        self._pack_labeled_entry(bar1, "[KWD]:", self.log_keyword_var, width=24)
        self._pack_toolbar_button(bar2, "[CMD] 查询", command=self.load_logs)
        log_delete_btn = self._pack_toolbar_button(bar2, "[CMD] 删除选中", command=self.delete_selected_log, style="Danger.TButton")
        log_delete_batch_btn = self._pack_toolbar_button(bar2, "[CMD] 按过滤批量删除", command=self.delete_filtered_logs, style="Danger.TButton")
        self._register_admin_only(log_delete_btn, log_delete_batch_btn)
        log_table = ttk.Frame(self.page_logs)
        log_table.pack(fill=tk.BOTH, expand=True)
        self.log_tree = self._create_headings_tree(
            log_table,
            columns=[
                ("id", "[ID]", 60),
                ("ts", "[TS]", 150),
                ("username", "[USERNAME]", 120),
                ("action", "[ACTION]", 170),
                ("target", "[TARGET]", 180),
                ("detail", "[DETAIL]", 620),
            ],
            height=23,
        )

    def _attach_tree_scrollbars(self, parent: tk.Widget, tree: ttk.Treeview) -> None:
        parent.columnconfigure(0, weight=1)
        parent.rowconfigure(0, weight=1)
        y_scroll = self._create_scrollbar(parent, orient=tk.VERTICAL, command=tree.yview)
        x_scroll = self._create_scrollbar(parent, orient=tk.HORIZONTAL, command=tree.xview)
        tree.configure(yscrollcommand=y_scroll.set, xscrollcommand=x_scroll.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y_scroll.grid(row=0, column=1, sticky="ns")
        x_scroll.grid(row=1, column=0, sticky="ew")

    def _create_scrollbar(self, parent: tk.Widget, orient: str, command) -> tk.Scrollbar:
        width = 9 if orient == tk.VERTICAL else 10
        return tk.Scrollbar(
            parent,
            orient=orient,
            command=command,
            width=width,
            relief=tk.FLAT,
            borderwidth=0,
            highlightthickness=0,
            elementborderwidth=0,
            troughcolor="#ECF1F6",
            bg="#C3D3E6",
            activebackground="#7FA6C9",
            activerelief=tk.FLAT,
        )

    def _create_text_view(
        self,
        parent: tk.Widget,
        *,
        height: int | None = None,
        bg: str = "#F5F7FA",
        wrap: str = tk.WORD,
    ) -> tk.Text:
        return tk.Text(
            parent,
            height=height,
            bg=bg,
            fg="#003366",
            insertbackground="#003366",
            relief=tk.SOLID,
            borderwidth=1,
            font=self.font_mono,
            wrap=wrap,
        )

    def _pack_text_view(
        self,
        parent: tk.Widget,
        *,
        side: str = tk.LEFT,
        fill: str = tk.BOTH,
        expand: bool = True,
        padx=6,
        pady=6,
        width: int | None = None,
        height: int | None = None,
        bg: str = "#F5F7FA",
        wrap: str = tk.WORD,
    ) -> tk.Text:
        text = self._create_text_view(parent, height=height, bg=bg, wrap=wrap)
        if width is not None:
            text.configure(width=width)
        text.pack(side=side, fill=fill, expand=expand, padx=padx, pady=pady)
        return text

    def _pack_labeled_entry(
        self,
        parent: tk.Widget,
        label_text: str,
        textvariable: tk.StringVar,
        *,
        width: int | None = None,
        show: str | None = None,
        label_width: int | None = None,
        label_padx=0,
        entry_padx=4,
        entry_pady=2,
        fill: str = tk.NONE,
        expand: bool = False,
    ) -> ttk.Entry:
        ttk.Label(parent, text=label_text, width=label_width, style="Hint.TLabel").pack(side=tk.LEFT, padx=label_padx)
        entry = ttk.Entry(parent, textvariable=textvariable, width=width, show=show)
        entry.pack(side=tk.LEFT, padx=entry_padx, pady=entry_pady, fill=fill, expand=expand)
        return entry

    def _pack_labeled_combobox(
        self,
        parent: tk.Widget,
        label_text: str,
        textvariable: tk.StringVar,
        values,
        *,
        width: int | None = None,
        label_width: int | None = None,
        label_padx=0,
        combo_padx=4,
        state: str = "readonly",
    ) -> ttk.Combobox:
        ttk.Label(parent, text=label_text, width=label_width, style="Hint.TLabel").pack(side=tk.LEFT, padx=label_padx)
        combo = ttk.Combobox(parent, textvariable=textvariable, values=values, width=width, state=state)
        combo.pack(side=tk.LEFT, padx=combo_padx)
        return combo

    def _pack_toolbar_button(
        self,
        parent: tk.Widget,
        text: str,
        *,
        command=None,
        style: str = "Secondary.TButton",
        side: str = tk.LEFT,
        padx=4,
        pady=0,
    ) -> ttk.Button:
        button = ttk.Button(parent, text=text, style=style, command=command)
        button.pack(side=side, padx=padx, pady=pady)
        return button

    def _grid_text_view(
        self,
        parent: tk.Widget,
        *,
        row: int,
        height: int | None = None,
        bg: str = "#F5F7FA",
        wrap: str = tk.WORD,
        padx=4,
        pady=(0, 4),
    ) -> tk.Text:
        text = self._create_text_view(parent, height=height, bg=bg, wrap=wrap)
        text.grid(row=row, column=0, sticky="nsew", padx=padx, pady=pady)
        return text

    def _grid_scrollable_text_view(
        self,
        parent: tk.Widget,
        *,
        row: int,
        height: int | None = None,
        bg: str = "#F5F7FA",
        wrap: str = tk.WORD,
        padx=4,
        pady=(0, 4),
    ) -> tk.Text:
        text = self._grid_text_view(parent, row=row, height=height, bg=bg, wrap=wrap, padx=padx, pady=pady)
        y_scroll = self._create_scrollbar(parent, orient=tk.VERTICAL, command=text.yview)
        y_scroll.grid(row=row, column=1, sticky="ns", pady=pady)
        text.configure(yscrollcommand=y_scroll.set)
        return text

    def _create_field_value_tree(
        self,
        parent: tk.Widget,
        *,
        height: int = 10,
        field_width: int = 280,
        value_width: int = 420,
    ) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=("value",), show="tree headings", height=height)
        tree.heading("#0", text="[FIELD]")
        tree.heading("value", text="[VALUE]")
        tree.column("#0", width=field_width, anchor=tk.W)
        tree.column("value", width=value_width, anchor=tk.W)
        self._attach_tree_scrollbars(parent, tree)
        self._setup_tree(tree)
        return tree

    def _create_headings_tree(
        self,
        parent: tk.Widget,
        *,
        columns: list[tuple[str, str, int]],
        height: int = 10,
    ) -> ttk.Treeview:
        tree = ttk.Treeview(parent, columns=tuple(name for name, _, _ in columns), show="headings", height=height)
        for name, heading, width in columns:
            tree.heading(name, text=heading)
            tree.column(name, width=width, anchor=tk.W)
        self._attach_tree_scrollbars(parent, tree)
        self._setup_tree(tree)
        return tree

    def _create_flow_result_tab(
        self,
        notebook: ttk.Notebook,
        *,
        title: str,
        columns: list[tuple[str, str, int]],
        detail_title: str,
        action_button_text: str = "",
    ) -> tuple[ttk.Treeview, tk.Text, ttk.Button | None]:
        tab = ttk.Frame(notebook)
        tab.columnconfigure(0, weight=1)
        tab.rowconfigure(0, weight=1)
        detail_row = 3 if action_button_text else 2
        tab.rowconfigure(detail_row, weight=1)
        notebook.add(tab, text=title)

        table = ttk.Frame(tab)
        table.grid(row=0, column=0, sticky="nsew", pady=(0, 4))
        tree = self._create_headings_tree(table, columns=columns, height=10)

        label_row = 1
        action_button = None
        if action_button_text:
            action_bar = ttk.Frame(tab)
            action_bar.grid(row=1, column=0, sticky="ew", pady=(0, 4))
            action_button = ttk.Button(action_bar, text=action_button_text, style="Secondary.TButton")
            action_button.pack(side=tk.LEFT)
            label_row = 2

        ttk.Label(tab, text=detail_title, style="Hint.TLabel").grid(row=label_row, column=0, sticky="w", pady=(2, 4))
        detail_text = self._grid_text_view(tab, row=label_row + 1, bg="#F0F4F8", pady=(0, 4))
        return tree, detail_text, action_button

    def _create_workbench_two_panel_tab(
        self,
        notebook: ttk.Notebook,
        *,
        title: str,
        left_title: str,
        right_title: str,
        left_weight: int = 3,
        right_weight: int = 2,
    ) -> tuple[ttk.Frame, ttk.LabelFrame, ttk.LabelFrame]:
        tab = ttk.Frame(notebook, padding=(0, 2, 0, 0))
        notebook.add(tab, text=title)
        tab.columnconfigure(0, weight=left_weight)
        tab.columnconfigure(1, weight=right_weight)
        tab.rowconfigure(0, weight=1)
        left = ttk.LabelFrame(tab, text=left_title, style="Card.TLabelframe")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        right = ttk.LabelFrame(tab, text=right_title, style="Card.TLabelframe")
        right.grid(row=0, column=1, sticky="nsew")
        return tab, left, right

    def _create_kpi_card(
        self,
        parent: ttk.LabelFrame,
        *,
        column: int,
        title: str,
        value_var: tk.StringVar,
        value_style: str = "KpiValue.TLabel",
        value_pady: tuple[int, int] = (6, 0),
    ) -> ttk.Label:
        card = ttk.Frame(parent, style="KpiCard.TFrame", padding=(12, 10))
        card.grid(row=0, column=column, padx=8, pady=8, sticky="nsew")
        ttk.Label(card, text=title, style="KpiTitle.TLabel").pack(anchor=tk.W)
        value_label = ttk.Label(card, textvariable=value_var, style=value_style)
        value_label.pack(anchor=tk.W, pady=value_pady)
        return value_label

    def _prepare_detail_dialog(self, dlg: tk.Toplevel, title: str, geometry: str, min_width: int, min_height: int) -> None:
        dlg.title(title)
        dlg.geometry(geometry)
        dlg.minsize(min_width, min_height)
        dlg.resizable(True, True)
        dlg.configure(bg="#F5F7FA")

    def _attach_dialog_sizegrip(self, dlg: tk.Toplevel) -> None:
        grip = ttk.Sizegrip(dlg, style="Grip.TSizegrip")
        grip.place(relx=1.0, rely=1.0, anchor="se")

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

    def _handle_ui_exception(self, exc_type, exc_value, exc_traceback) -> None:
        traceback.print_exception(exc_type, exc_value, exc_traceback)
        messagebox.showerror("ERR_UI", f"{exc_type.__name__}: {exc_value}")

    def _set_traffic_tools_panel(self, expanded: bool) -> None:
        self._traffic_tools_expanded = bool(expanded)
        if self._traffic_tools_expanded:
            self.traffic_tools_panel.pack(fill=tk.X, pady=(0, 4))
            self.traffic_tools_toggle_var.set("[LESS] 收起高级操作")
        else:
            self.traffic_tools_panel.pack_forget()
            self.traffic_tools_toggle_var.set("[MORE] 展开高级操作")

    def _toggle_traffic_tools_panel(self) -> None:
        self._set_traffic_tools_panel(not self._traffic_tools_expanded)

    def _register_admin_only(self, *widgets: tk.Widget) -> None:
        for widget in widgets:
            self._admin_only_controls.append(widget)

    def _update_permission_controls(self) -> None:
        readonly = self.is_authenticated and (not self._is_admin())
        for widget in self._admin_only_controls:
            try:
                widget.configure(state=tk.DISABLED if readonly else tk.NORMAL)
            except tk.TclError:
                continue

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
        self._update_permission_controls()
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
        self._update_permission_controls()
        self._route_to("realtime")
        self.login_user_var.set("")
        self.login_pass_var.set("")
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

    @staticmethod
    def _needs_ctf_packet_detail(row: dict) -> bool:
        if str(row.get("raw_hex", "") or "").strip():
            return False
        ports = {int(row.get("src_port", 0) or 0), int(row.get("dst_port", 0) or 0)}
        risk = str(row.get("risk_level", "normal") or "normal").lower()
        return bool(
            ports & CTF_DETAIL_INTERESTING_PORTS
            or int(row.get("length", 0) or 0) >= CTF_LARGE_PAYLOAD_BYTES
            or risk in {"high", "medium"}
        )

    def _prefetch_ctf_packet_details(self, rows: list[dict]) -> dict[int, dict]:
        candidate_ids = [int(row.get("id", 0) or 0) for row in rows[:CTF_MAX_PACKET_CLUES] if self._needs_ctf_packet_detail(row)]
        detail_map = self.runtime.query_packet_details(candidate_ids, include_related_alerts=False)
        for packet_id, detail in detail_map.items():
            try:
                self._put_cached_packet_detail(packet_id, detail)
            except Exception:
                pass
        return detail_map

    def _prefetch_ctf_frame_details(self, frames: list[dict]) -> dict[int, dict]:
        frame_ids = [int(row.get("id", 0) or 0) for row in frames[:CTF_MAX_FRAME_CLUES]]
        return self.runtime.query_offline_frame_details(frame_ids)

    def _packet_page_size(self) -> int:
        try:
            return max(50, min(2000, int(self.packet_page_size_var.get() or 500)))
        except Exception:
            return 500

    def _load_prev_packet_page(self) -> None:
        if self._packet_page <= 1:
            return
        self.load_packets(page=self._packet_page - 1, reset_page=False)

    def _load_next_packet_page(self) -> None:
        if self._packet_page >= self._packet_total_pages:
            return
        self.load_packets(page=self._packet_page + 1, reset_page=False)

    def _update_packet_page_info(self) -> None:
        self.packet_page_info_var.set(f"页 {self._packet_page}/{max(1, self._packet_total_pages)} | 命中 {self._packet_total_rows} 条")

    def load_packets(self, page: int | None = None, reset_page: bool = True) -> None:
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
        target_page = 1 if reset_page else max(1, int(page or self._packet_page or 1))
        self._reset_packet_view_state(target_page)
        self._clear_packet_related_views()
        self._reset_packet_panel_texts()
        self.packet_import_status_var.set(self._packet_query_pending_status(target_page))
        self._reset_packet_query_runtime(target_page)

        def worker() -> None:
            try:
                self._packet_query_result = self._query_packet_page_result(target_page, process_name, ip, source, expr, only_abnormal, sort_key, sort_desc)
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
        result = self._consume_packet_query_result()
        rows, offline_view = self._apply_packet_query_result(result, source_filter)
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

    @staticmethod
    def _clear_tree(tree: ttk.Treeview) -> None:
        for item in tree.get_children():
            tree.delete(item)

    def _reset_packet_view_state(self, page: int) -> None:
        self._packet_rows_in_view = []
        self._packet_time_base = 0.0
        self._current_packet_detail = None
        self._current_frame_detail = None
        self._packet_page = page
        self._packet_total_pages = 1
        self._packet_total_rows = 0
        self._packet_virtual_enabled = False
        self._packet_virtual_window_start = 0
        self._update_packet_page_info()

    def _clear_packet_related_views(self) -> None:
        self._packet_tree_id_map.clear()
        self._session_tree_id_map.clear()
        self._frame_tree_id_map.clear()
        self._ctf_clue_tree_id_map.clear()
        self._session_rows_in_view = []
        self._frame_rows_in_view = []
        self._ctf_clue_rows_in_view = []
        for tree in (self.packet_tree, self.packet_detail_tree, self.session_tree, self.frame_tree, self.ctf_clue_tree):
            self._clear_tree(tree)

    def _reset_packet_panel_texts(self) -> None:
        for widget, text_key in (
            (self.packet_summary_text, "packet_summary"),
            (self.packet_expert_text, "packet_expert"),
            (self.packet_detail_text, "packet_detail"),
            (self.session_summary_text, "session_summary"),
            (self.frame_summary_text, "frame_summary"),
            (self.frame_detail_text, "frame_detail"),
            (self.ctf_clue_text, "ctf_clue"),
        ):
            self._set_text_content(widget, DEFAULT_PACKET_PANEL_TEXTS[text_key])

    def _reset_alert_panel_texts(self) -> None:
        self._set_text_content(self.attack_desc_text, DEFAULT_ALERT_PANEL_TEXTS["attack_desc"])
        self._set_text_content(self.attack_stats_text, DEFAULT_ALERT_PANEL_TEXTS["attack_stats"])

    def _empty_packet_query_result(self, page: int) -> dict:
        return {"rows": [], "total": 0, "page": page, "page_size": self._packet_page_size(), "total_pages": 1, "frame_rows": [], "frame_total": 0, "frame_total_pages": 1}

    def _reset_packet_query_runtime(self, page: int) -> None:
        self._packet_query_done = False
        self._packet_query_error = ""
        self._packet_query_result = self._empty_packet_query_result(page)

    @staticmethod
    def _packet_query_pending_status(page: int) -> str:
        return f"流量窗口加载中: 正在查询第 {int(page)} 页并准备渲染..."

    def _packet_query_progress_status(self, rendered_rows: int, page_rows: int) -> str:
        return f"流量窗口加载中: 第 {self._packet_page}/{self._packet_total_pages} 页 | 本页 {int(rendered_rows)}/{int(page_rows)} | 命中总数 {self._packet_total_rows}"

    def _packet_query_complete_status(self, page_rows: int) -> str:
        return f"流量窗口已完成: 第 {self._packet_page}/{self._packet_total_pages} 页 | 本页 {int(page_rows)} 条 | 命中总数 {self._packet_total_rows}"

    def _consume_packet_query_result(self) -> dict:
        result = dict(self._packet_query_result)
        self._packet_query_result = self._empty_packet_query_result(self._packet_page)
        return result

    def _apply_packet_query_result(self, result: dict, source_filter: str) -> tuple[list[dict], bool]:
        rows = list(result.get("rows", []))
        self._packet_page = int(result.get("page", 1) or 1)
        self._packet_total_pages = int(result.get("total_pages", 1) or 1)
        self._packet_total_rows = int(result.get("total", 0) or 0)
        self._update_packet_page_info()
        self._packet_rows_in_view = rows
        self._refresh_session_view(rows)
        self._refresh_frame_view(
            list(result.get("frame_rows", [])),
            int(result.get("frame_total", 0) or 0),
            int(result.get("frame_total_pages", 1) or 1),
        )
        self._refresh_ctf_clue_view(rows)
        ts_epochs = [float(r.get("ts_epoch", 0.0) or 0.0) for r in rows if float(r.get("ts_epoch", 0.0) or 0.0) > 0]
        self._packet_time_base = min(ts_epochs) if ts_epochs else 0.0
        self._packet_detail_cache.clear()
        self._packet_detail_cache_order.clear()
        self._packet_virtual_enabled = False
        self._packet_virtual_window_start = 0
        offline_view = str(source_filter).strip().lower() == "offline"
        self.packet_import_status_var.set(self._packet_query_progress_status(0, len(rows)))
        if offline_view and (not rows) and int(result.get("frame_total", 0) or 0) > 0:
            self.traffic_workbench.select(self.traffic_frame_tab)
        return rows, offline_view

    @staticmethod
    def _flow_tracking_status(state: str, packet_id: int | None = None, row_count: int = 0) -> str:
        normalized = str(state or "").strip().lower()
        if normalized == "loading":
            return f"流量窗口加载中: 正在追踪会话 ID={int(packet_id or 0)} ..."
        if normalized == "failed":
            return "流量窗口会话追踪失败"
        if normalized == "empty":
            return "流量窗口会话追踪未命中"
        return f"流量窗口会话追踪完成: {int(row_count)} 条"

    @staticmethod
    def _offline_import_start_status(file_name: str, profile) -> str:
        return (
            f"离线分析状态: 正在处理 {file_name} | mode={profile.mode} | "
            f"threads={profile.parser_threads} | cpu_limit={profile.cpu_limit_percent}%"
        )

    @staticmethod
    def _offline_import_progress_status(progress: dict) -> str:
        pct = float(progress.get("percent", 0.0))
        mode = str(progress.get("mode", "balanced"))
        parser_threads = int(progress.get("parser_threads", 1) or 1)
        cpu_limit = int(progress.get("cpu_limit_percent", 0) or 0)
        return (
            f"离线分析状态: {pct:.1f}% | mode={mode} | threads={parser_threads} | "
            f"cpu_limit={cpu_limit}% | 网络包 {progress.get('processed', 0)} | "
            f"通用帧 {progress.get('generic_frames', 0)} | 告警 {progress.get('alerts', 0)}"
        )

    @staticmethod
    def _offline_import_complete_status(mode: str, packets: int, frames: int, alerts: int) -> str:
        return f"离线分析状态: 完成，mode={mode}, packets={int(packets)}, frames={int(frames)}, alerts={int(alerts)}"

    @staticmethod
    def _offline_import_audit_detail(mode: str, packets: int, frames: int, alerts: int) -> str:
        return f"mode={mode},packets={int(packets)},frames={int(frames)},alerts={int(alerts)}"

    @staticmethod
    def _focus_first_tree_item(tree: ttk.Treeview) -> str | None:
        children = tree.get_children()
        if not children:
            return None
        tree.selection_set(children[0])
        tree.focus(children[0])
        return str(children[0])

    @staticmethod
    def _tree_selected_index(tree: ttk.Treeview, index_map: dict[str, int], row_count: int) -> int:
        selected = tree.selection()
        if not selected:
            return -1
        index = index_map.get(selected[0], -1)
        return index if 0 <= index < row_count else -1

    def _populate_indexed_tree(
        self,
        tree: ttk.Treeview,
        rows: list[dict],
        index_map: dict[str, int],
        value_builder,
        empty_widget: tk.Text,
        empty_text: str,
        on_select,
    ) -> None:
        index_map.clear()
        self._clear_tree(tree)
        for index, row in enumerate(rows):
            item_id = tree.insert("", tk.END, values=value_builder(row))
            index_map[item_id] = index
        if rows:
            if self._focus_first_tree_item(tree):
                on_select()
            return
        self._set_text_content(empty_widget, empty_text)

    @staticmethod
    def _offline_frame_search_text(process_name: str, ip: str) -> str:
        return " ".join(term for term in (ip, process_name) if term).strip()

    def _query_packet_page_result(
        self,
        page: int,
        process_name: str,
        ip: str,
        source: str,
        expr: str,
        only_abnormal: bool,
        sort_key: str,
        sort_desc: bool,
    ) -> dict:
        result = self.runtime.query_packets_page(
            page=page,
            page_size=self._packet_page_size(),
            process_name=process_name,
            ip=ip,
            source=source,
            rule_expr=expr,
            only_abnormal=only_abnormal,
            sort_key=sort_key,
            sort_desc=sort_desc,
        )
        if str(source).strip().lower() != "offline":
            return result
        frame_result = self.runtime.query_offline_frames_page(
            page=page,
            page_size=self._packet_page_size(),
            search_text=self._offline_frame_search_text(process_name, ip),
        )
        result["frame_rows"] = list(frame_result.get("rows", []))
        result["frame_total"] = int(frame_result.get("total", 0) or 0)
        result["frame_total_pages"] = int(frame_result.get("total_pages", 1) or 1)
        return result

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
            app = next((label for ports, label in PACKET_APP_HINT_PORTS if {src_port, dst_port} & ports), "")
            return f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}  TCP Len={length} {app}".strip()
        if proto == "UDP":
            app = "DNS?" if {src_port, dst_port} & {53} else ""
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

    @staticmethod
    def _risk_rank(risk_value: str) -> int:
        rv = str(risk_value or "").strip().lower()
        if rv in {"high", "高", "高风险"}:
            return 3
        if rv in {"medium", "中", "中风险"}:
            return 2
        if rv in {"low", "低", "低风险"}:
            return 1
        return 0

    @staticmethod
    def _risk_label_cn(risk_value: str) -> str:
        rv = str(risk_value or "").strip().lower()
        if rv == "high":
            return "高风险"
        if rv == "medium":
            return "中风险"
        if rv == "low":
            return "低风险"
        return "正常"

    def _describe_packet_direction(self, src_ip: str, dst_ip: str) -> str:
        src_private = self._is_private_ip(src_ip)
        dst_private = self._is_private_ip(dst_ip)
        if src_private and not dst_private:
            return "本机/内网 -> 公网"
        if (not src_private) and dst_private:
            return "公网 -> 本机/内网"
        if src_private and dst_private:
            return "内网横向通信"
        return "公网通信"

    def _build_packet_summary_lines(self, detail: dict, risk_value: str, alerts: list[dict]) -> list[str]:
        src_ip = str(detail.get("src_ip", "") or "")
        dst_ip = str(detail.get("dst_ip", "") or "")
        src_port = int(detail.get("src_port", 0) or 0)
        dst_port = int(detail.get("dst_port", 0) or 0)
        process_name = str(detail.get("process_name", "") or "-").strip() or "-"
        app_proto, app_fields = extract_app_fields(detail)
        direction = self._describe_packet_direction(src_ip, dst_ip)
        risk = str(risk_value or "normal").lower()
        risk_label = self._risk_label_cn(risk)
        lines = [
            "流量摘要:",
            f"- 连接类型: {app_proto} | 协议: {str(detail.get('proto', '') or '').upper() or 'OTHER'} | 风险: {risk_label}",
            f"- 通信方向: {direction}",
            f"- 会话端点: {src_ip}:{src_port} -> {dst_ip}:{dst_port}",
            f"- 关联进程: {process_name} | 长度: {int(detail.get('length', 0) or 0)} 字节 | 来源: {detail.get('source', '') or '-'}",
            f"- 关联告警: {len(alerts)} 条",
        ]
        lines.extend(self._build_packet_app_summary_lines(app_proto, app_fields))
        lines.append(f"- 建议动作: {self._packet_recommendation(risk, app_proto)}")
        return lines

    @staticmethod
    def _packet_recommendation(risk: str, app_proto: str) -> str:
        if risk == "high":
            return "建议优先排查该连接，并查看完整会话与原始载荷。"
        if risk == "medium":
            return "建议结合关联告警与实战线索继续缩小范围。"
        if app_proto in {"Telnet", "FTP", "POP3", "IMAP"}:
            return "该连接可能是明文协议，建议检查是否含凭据或敏感文本。"
        if app_proto in {"DNS", "QUIC"}:
            return "建议关注域名、长度分布和会话频率，判断是否有隧道或异常外联。"
        return "当前未见明显异常，可继续看会话走势。"

    @staticmethod
    def _build_packet_app_summary_lines(app_proto: str, app_fields: dict) -> list[str]:
        lines: list[str] = []
        if app_proto == "HTTP":
            if app_fields.get("method") or app_fields.get("path"):
                lines.append(f"- HTTP 请求: {app_fields.get('method', '')} {app_fields.get('path', '')}".strip())
            elif app_fields.get("status_code"):
                lines.append(f"- HTTP 响应: {app_fields.get('status_code', '')} {app_fields.get('status_text', '')}".strip())
            if app_fields.get("host"):
                lines.append(f"- 目标主机: {app_fields.get('host', '')}")
            return lines
        if app_proto == "DNS" and app_fields.get("query"):
            return [f"- DNS 查询: {app_fields.get('query', '')} ({app_fields.get('query_type', '')})"]
        if app_proto == "Modbus/TCP":
            lines.append(f"- Modbus: unit={app_fields.get('unit_id', '-')} | func={app_fields.get('function_name', '-')}")
            if app_fields.get("target"):
                lines.append(f"- 操作目标: {app_fields.get('target', '')}")
            if app_fields.get("data_preview"):
                lines.append(f"- 数据预览: {app_fields.get('data_preview', '')}")
            return lines
        if app_proto == "TLS":
            if app_fields.get("sni"):
                lines.append(f"- TLS SNI: {app_fields.get('sni', '')}")
            if app_fields.get("alpn"):
                lines.append(f"- ALPN: {app_fields.get('alpn', '')}")
        return lines

    def _render_packet_summary_card(self, detail: dict, risk_value: str, alerts: list[dict]) -> None:
        self._set_text_content(self.packet_summary_text, "\n".join(self._build_packet_summary_lines(detail, risk_value, alerts)))

    def _session_key(self, row: dict) -> tuple:
        left = (str(row.get("src_ip", "") or ""), int(row.get("src_port", 0) or 0))
        right = (str(row.get("dst_ip", "") or ""), int(row.get("dst_port", 0) or 0))
        if left <= right:
            pair = (left, right)
        else:
            pair = (right, left)
        return (
            str(row.get("source", "") or ""),
            str(row.get("proto", "") or "").upper(),
            pair,
        )

    def _build_session_bucket(self, row: dict) -> dict:
        app_proto, app_fields = extract_app_fields(row)
        target_hint = app_fields.get("host") or app_fields.get("query") or app_fields.get("sni") or str(row.get("dst_ip", "") or "")
        return {
            "rep_packet_id": int(row.get("id", 0) or 0),
            "proto": str(row.get("proto", "") or "").upper(),
            "source": str(row.get("source", "") or ""),
            "src_ip": str(row.get("src_ip", "") or ""),
            "dst_ip": str(row.get("dst_ip", "") or ""),
            "src_port": int(row.get("src_port", 0) or 0),
            "dst_port": int(row.get("dst_port", 0) or 0),
            "process_name": str(row.get("process_name", "") or "-").strip() or "-",
            "app": app_proto,
            "direction": self._describe_packet_direction(str(row.get("src_ip", "")), str(row.get("dst_ip", ""))),
            "peer": target_hint[:180],
            "packets": 0,
            "bytes": 0,
            "risk_rank": 0,
            "risk": "normal",
            "first_ts": str(row.get("ts", "") or ""),
            "last_ts": str(row.get("ts", "") or ""),
        }

    def _update_session_bucket(self, bucket: dict, row: dict) -> None:
        bucket["packets"] += 1
        bucket["bytes"] += int(row.get("length", 0) or 0)
        bucket["last_ts"] = str(row.get("ts", "") or bucket["last_ts"])
        risk_rank = self._risk_rank(str(row.get("risk_level", "normal")))
        if risk_rank >= int(bucket["risk_rank"]):
            bucket["risk_rank"] = risk_rank
            bucket["risk"] = str(row.get("risk_level", "normal") or "normal").lower()

    def _insert_session_tree_row(self, row: dict) -> None:
        item_id = self.session_tree.insert(
            "",
            tk.END,
            values=(row["app"], row["direction"], row["process_name"], row["peer"], row["packets"], row["bytes"], self._risk_label_cn(str(row["risk"]))),
        )
        self._session_tree_id_map[item_id] = int(row["rep_packet_id"])

    def _refresh_session_view(self, rows: list[dict]) -> None:
        self._session_rows_in_view = []
        self._session_tree_id_map.clear()
        self._clear_tree(self.session_tree)
        if not rows:
            self._set_text_content(self.session_summary_text, "当前筛选结果没有可展示的会话。")
            return
        buckets: dict[tuple, dict] = {}
        for row in rows:
            key = self._session_key(row)
            bucket = buckets.setdefault(key, self._build_session_bucket(row))
            self._update_session_bucket(bucket, row)
        ordered = sorted(
            buckets.values(),
            key=lambda item: (-int(item["risk_rank"]), -int(item["bytes"]), -int(item["packets"])),
        )
        self._session_rows_in_view = ordered
        for row in ordered:
            self._insert_session_tree_row(row)
        lines = [
            "会话概览:",
            f"- 当前页共 {len(rows)} 条流量，聚合出 {len(ordered)} 条会话。",
            f"- 高风险会话 {sum(1 for item in ordered if item['risk'] == 'high')} 条，中风险会话 {sum(1 for item in ordered if item['risk'] == 'medium')} 条。",
            "- 双击会话可直接打开完整会话追踪；适合先按连接排查，再回到数据包看细节。",
        ]
        self._set_text_content(self.session_summary_text, "\n".join(lines))
        if self._focus_first_tree_item(self.session_tree):
            self._on_session_select()

    def _refresh_frame_view(self, rows: list[dict], total: int, total_pages: int) -> None:
        self._frame_rows_in_view = list(rows)
        self._frame_tree_id_map.clear()
        self._clear_tree(self.frame_tree)
        if not rows:
            self._set_text_content(self.frame_summary_text, "当前离线文件没有可展示的通用帧，或当前来源不是离线文件。")
            return
        for row in rows:
            item_id = self.frame_tree.insert(
                "",
                tk.END,
                values=(
                    row.get("frame_no", 0),
                    row.get("ts", ""),
                    row.get("linktype", 0),
                    row.get("iface", ""),
                    row.get("frame_type", ""),
                    row.get("wirelen", 0),
                    row.get("summary", ""),
                ),
            )
            self._frame_tree_id_map[item_id] = int(row.get("id", 0) or 0)
        lines = [
            "通用帧概览:",
            f"- 当前页显示 {len(rows)} 条通用帧，总计 {total} 条，页数 {max(1, total_pages)}。",
            "- 这里会保留离线文件中的原始帧，即使当前还不能解析成标准网络包，也能继续看链路类型、长度和原始字节。",
            "- 如果“数据包”页为空但这里有内容，通常说明文件属于 USB、特殊链路或非 IP 抓包。",
        ]
        self._set_text_content(self.frame_summary_text, "\n".join(lines))
        if self._focus_first_tree_item(self.frame_tree):
            self._on_frame_select()

    def _selected_frame_row(self) -> dict | None:
        selected = self.frame_tree.selection()
        if not selected:
            return None
        index = self.frame_tree.index(selected[0])
        if index < 0 or index >= len(self._frame_rows_in_view):
            return None
        return self._frame_rows_in_view[index]

    def _render_current_frame_raw(self) -> None:
        if not self._current_frame_detail:
            return
        raw_hex = str(self._current_frame_detail.get("raw_hex", "") or "")
        mode = self.frame_raw_mode_var.get().strip().lower()
        content = self._decode_raw_by_mode(raw_hex, mode)
        self._set_text_content(self.frame_detail_text, content)

    def _on_frame_select(self, _event=None) -> None:
        row = self._selected_frame_row()
        if not row:
            return
        frame_id = int(row.get("id", 0) or 0)
        detail = self.runtime.query_offline_frame_detail(frame_id) or row
        self._current_frame_detail = detail
        intel = extract_frame_intel(detail)
        lines = [
            "帧摘要:",
            f"- 帧号: {detail.get('frame_no', 0)} | 链路类型: {detail.get('linktype', 0)} ({detail.get('frame_type', '')})",
            f"- 时间: {detail.get('ts', '')} | 接口: {detail.get('iface', '') or '-'}",
            f"- 捕获长度: {detail.get('caplen', 0)} | 线长: {detail.get('wirelen', 0)} | 来源: {detail.get('source', '') or '-'}",
            f"- 摘要: {detail.get('summary', '')}",
            "- 建议: 若“数据包”页没有内容，先从这里看原始字节、ASCII 线索和链路类型，再决定是否需要专门协议解析。",
        ]
        if intel.get("summary"):
            lines.insert(4, f"- 实战线索: {intel.get('summary', '')}")
        for key, value in dict(intel.get("fields", {})).items():
            lines.append(f"- {key}: {value}")
        self._set_text_content(self.frame_summary_text, "\n".join(lines))
        self._render_current_frame_raw()

    def _refresh_ctf_clue_view(self, rows: list[dict]) -> None:
        self._ctf_clue_rows_in_view = []
        self._ctf_clue_tree_id_map.clear()
        self._clear_tree(self.ctf_clue_tree)
        prefetched_frames = self._prefetch_ctf_frame_details(self._frame_rows_in_view)
        frame_clues = build_frame_ctf_clues(list(prefetched_frames.values()))
        if not rows and not frame_clues:
            self._set_text_content(self.ctf_clue_text, "当前筛选结果没有可提取的实战线索。")
            return
        prefetched_details = self._prefetch_ctf_packet_details(rows)
        clues = build_packet_ctf_clues(
            rows,
            prefetched_details,
            max_rows=CTF_MAX_PACKET_CLUES,
            large_payload_bytes=CTF_LARGE_PAYLOAD_BYTES,
        ) + frame_clues
        clues.sort(key=lambda item: (-self._risk_rank(str(item.get("level_key", ""))), item["type"], item["summary"]))
        clues = clues[:80]
        self._ctf_clue_rows_in_view = clues
        for idx, row in enumerate(clues):
            item_id = self.ctf_clue_tree.insert("", tk.END, values=(row["level"], row["type"], row["summary"], row["filter"]))
            self._ctf_clue_tree_id_map[item_id] = idx
        headline = [
            "实战线索:",
            f"- 当前页从 {len(rows)} 条流量提取出 {len(clues)} 条优先线索。",
            "- 双击线索可直接把推荐过滤条件填回查询区，适合快速缩小题目范围。",
        ]
        self._set_text_content(self.ctf_clue_text, "\n".join(headline))
        if self._focus_first_tree_item(self.ctf_clue_tree):
            self._on_ctf_clue_select()

    def _select_frame_by_id(self, frame_id: int, switch_to_frame: bool = True) -> bool:
        target = int(frame_id)
        if switch_to_frame:
            self.traffic_workbench.select(self.traffic_frame_tab)
        for item_id, mapped_id in self._frame_tree_id_map.items():
            if int(mapped_id) == target and self.frame_tree.exists(item_id):
                self.frame_tree.selection_set(item_id)
                self.frame_tree.focus(item_id)
                self.frame_tree.see(item_id)
                self._on_frame_select()
                return True
        return False

    def _session_row_from_selection(self) -> dict | None:
        selected = self.session_tree.selection()
        if not selected:
            return None
        index = self.session_tree.index(selected[0])
        if index < 0 or index >= len(self._session_rows_in_view):
            return None
        return self._session_rows_in_view[index]

    def _on_session_select(self, _event=None) -> None:
        row = self._session_row_from_selection()
        if not row:
            return
        lines = [
            "会话摘要:",
            f"- 应用协议: {row['app']} | 风险: {self._risk_label_cn(str(row['risk']))} | 来源: {row['source'] or '-'}",
            f"- 方向: {row['direction']}",
            f"- 端点: {row['src_ip']}:{row['src_port']} <-> {row['dst_ip']}:{row['dst_port']}",
            f"- 进程: {row['process_name']} | 包数: {row['packets']} | 总字节: {row['bytes']}",
            f"- 时间范围: {row['first_ts']} ~ {row['last_ts']}",
            "- 建议: 双击直接打开完整会话追踪；若要看字段细节，再切到“数据包”标签。",
        ]
        self._set_text_content(self.session_summary_text, "\n".join(lines))

    def _select_packet_by_id(self, packet_id: int, switch_to_packet: bool = True) -> bool:
        target = int(packet_id)
        if switch_to_packet:
            self.traffic_workbench.select(self.traffic_packet_tab)
        for item_id, mapped_id in self._packet_tree_id_map.items():
            if int(mapped_id) == target and self.packet_tree.exists(item_id):
                self.packet_tree.selection_set(item_id)
                self.packet_tree.focus(item_id)
                self.packet_tree.see(item_id)
                self._on_packet_select()
                return True
        return False

    def _focus_selected_session_packet(self) -> None:
        row = self._session_row_from_selection()
        if not row:
            messagebox.showwarning("ERR_INPUT", "请先选择一条会话。")
            return
        if not self._select_packet_by_id(int(row.get("rep_packet_id", 0) or 0), switch_to_packet=True):
            messagebox.showwarning("ERR_DATA", "当前页未找到该会话代表流量，可先重新查询或直接打开会话追踪。")

    def _open_flow_view_for_packet_id(self, packet_id: int) -> None:
        pid = int(packet_id)
        if pid <= 0:
            return
        self.packet_import_status_var.set(self._flow_tracking_status("loading", packet_id=pid))
        result: dict[str, object] = {"rows": [], "error": ""}
        self._packet_flow_query_token += 1
        token = self._packet_flow_query_token

        def worker() -> None:
            try:
                detail = self.runtime.query_packet_detail(pid)
                rows = self.runtime.query_flow_packets(pid, limit=3000)
                result["rows"] = rows
                if detail and rows:
                    result["analysis"] = self.runtime.flow_workbench.analyze_flow(
                        rows=rows,
                        anchor_src=str(detail.get("src_ip", "") or ""),
                        anchor_sport=int(detail.get("src_port", 0) or 0),
                        direction_mode="interleaved",
                    )
            except Exception as e:
                result["error"] = str(e)

        def apply_result() -> None:
            if token != self._packet_flow_query_token:
                return
            err = str(result.get("error", "")).strip()
            if err:
                self.packet_import_status_var.set(self._flow_tracking_status("failed"))
                messagebox.showerror("ERR_FLOW", err)
                return
            rows = list(result.get("rows", []))
            if not rows:
                self.packet_import_status_var.set(self._flow_tracking_status("empty"))
                messagebox.showwarning("ERR_DATA", "未找到该包对应的会话流。")
                return
            analysis = result.get("analysis") or self.runtime.flow_workbench.analyze_flow(
                rows=rows,
                anchor_src=str(rows[0].get("src_ip", "") or ""),
                anchor_sport=int(rows[0].get("src_port", 0) or 0),
                direction_mode="interleaved",
            )
            self._show_follow_stream_viewer(rows, analysis)
            self.packet_import_status_var.set(self._flow_tracking_status("done", row_count=len(rows)))

        threading.Thread(target=lambda: (worker(), self.root.after(0, apply_result)), daemon=True).start()

    def _open_selected_session_flow(self) -> None:
        row = self._session_row_from_selection()
        if not row:
            messagebox.showwarning("ERR_INPUT", "请先选择一条会话。")
            return
        self._open_flow_view_for_packet_id(int(row.get("rep_packet_id", 0) or 0))

    def _selected_ctf_clue(self) -> dict | None:
        selected = self.ctf_clue_tree.selection()
        if not selected:
            return None
        index = self._ctf_clue_tree_id_map.get(selected[0], -1)
        if index < 0 or index >= len(self._ctf_clue_rows_in_view):
            return None
        return self._ctf_clue_rows_in_view[index]

    def _on_ctf_clue_select(self, _event=None) -> None:
        row = self._selected_ctf_clue()
        if not row:
            return
        lines = [
            "线索解读:",
            f"- 级别: {row['level']} | 类型: {row['type']}",
            f"- 摘要: {row['summary']}",
            f"- 推荐过滤: {row['filter']}",
            f"- 建议: {row['detail']}",
            "- 操作: 可双击直接应用过滤，或跳转到代表数据包继续看协议细节。",
        ]
        self._set_text_content(self.ctf_clue_text, "\n".join(lines))

    def _build_follow_stream_lines(self, rows: list[dict], mode: str, anchor_src: str, anchor_sport: int) -> list[str]:
        lines: list[str] = []
        for idx, row in enumerate(rows, start=1):
            src = str(row.get("src_ip", ""))
            dst = str(row.get("dst_ip", ""))
            sport = int(row.get("src_port", 0) or 0)
            dport = int(row.get("dst_port", 0) or 0)
            direction = "C->S" if (src == anchor_src and sport == anchor_sport) else "S->C"
            head = f"[{idx:04d}] {row.get('ts', '')} {direction} {src}:{sport} -> {dst}:{dport} LEN={row.get('length', 0)}"
            payload = self._decode_raw_by_mode(str(row.get("raw_hex", "")), mode)
            lines.extend([head, payload if payload else "(empty)", ""])
        return lines

    def _apply_selected_ctf_filter(self) -> None:
        row = self._selected_ctf_clue()
        if not row:
            messagebox.showwarning("ERR_INPUT", "请先选择一条线索。")
            return
        if str(row.get("target_kind", "") or "") == "frame":
            if not self._select_frame_by_id(int(row.get("frame_id", 0) or 0), switch_to_frame=True):
                self.traffic_workbench.select(self.traffic_frame_tab)
            return
        self.packet_rule_expr_var.set(str(row.get("filter", "") or ""))
        self.traffic_workbench.select(self.traffic_packet_tab)
        self.load_packets(reset_page=True)

    def _jump_to_ctf_packet(self) -> None:
        row = self._selected_ctf_clue()
        if not row:
            messagebox.showwarning("ERR_INPUT", "请先选择一条线索。")
            return
        if str(row.get("target_kind", "") or "") == "frame":
            if not self._select_frame_by_id(int(row.get("frame_id", 0) or 0), switch_to_frame=True):
                messagebox.showwarning("ERR_DATA", "当前页未找到该线索对应的原始帧。")
            return
        if not self._select_packet_by_id(int(row.get("packet_id", 0) or 0), switch_to_packet=True):
            messagebox.showwarning("ERR_DATA", "当前页未找到该线索对应的数据包。")

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
        self.packet_import_status_var.set(self._packet_query_progress_status(end, len(rows)))
        if end < len(rows):
            self._packet_render_job = self.root.after(
                1,
                lambda: self._render_packet_rows_chunk(token=token, rows=rows, start=end, offline_view=offline_view),
            )
            return
        self._packet_render_job = None
        self.packet_import_status_var.set(self._packet_query_complete_status(len(rows)))

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
        ports = {src_port, dst_port}
        layers = dissect_packet_bytes(detail)
        payload_bytes = bytes(layers.get("payload_bytes", b"") or b"")
        ascii_preview = extract_ascii(payload_bytes).lower()
        app_proto, app_fields = extract_app_fields(detail)

        if str(risk_value).lower() in {"high", "medium"}:
            findings.append(f"[{str(risk_value).upper()}] 当前流量已被风险关联标记。")
        if alerts:
            findings.append(f"关联告警 {len(alerts)} 条，最近子类: {alerts[0].get('sub_category', '')}")
        findings.extend(self._build_app_expert_findings(app_proto, app_fields))
        if proto == "TCP" and ports & PLAINTEXT_RISK_PORTS:
            findings.append("检测到明文协议常见端口（FTP/Telnet/POP3/IMAP），存在凭据泄露风险。")
        keyword_hits = [keyword for keyword in EXPERT_SENSITIVE_KEYWORDS if keyword in ascii_preview]
        if keyword_hits:
            findings.append(f"载荷命中敏感关键词: {', '.join(keyword_hits[:5])}")
        if self._is_private_ip(src_ip) and (not self._is_private_ip(dst_ip)):
            findings.append("流向特征: 私网 -> 公网，可关注外联/外传行为。")
        if proto in {"UDP", "TCP"} and 53 in ports:
            findings.append("检测到DNS通道，可进一步按域名/长度分布排查隧道行为。")
        if not findings:
            findings.append("未发现明显异常启发式特征，建议结合会话追踪与过滤器进一步排查。")
        return findings

    @staticmethod
    def _build_app_expert_findings(app_proto: str, app_fields: dict) -> list[str]:
        findings: list[str] = []
        for enabled, line in (
            (app_proto == "HTTP" and bool(app_fields.get("first_line")), f"HTTP首行: {app_fields.get('first_line', '')}"),
            (app_proto == "HTTP" and bool(app_fields.get("host")), f"HTTP Host: {app_fields.get('host', '')}"),
            (app_proto == "DNS" and bool(app_fields.get("query")), f"DNS {app_fields.get('qr', 'query')}: {app_fields.get('query', '')} ({app_fields.get('query_type', '')})"),
            (app_proto == "TLS" and bool(app_fields.get("sni")), f"TLS SNI: {app_fields.get('sni', '')}"),
            (app_proto == "TLS" and bool(app_fields.get("alpn")), f"TLS ALPN: {app_fields.get('alpn', '')}"),
        ):
            if enabled:
                findings.append(line)
        if app_proto != "Modbus/TCP":
            return findings
        findings.append(f"检测到 Modbus/TCP {app_fields.get('direction', '')}: {app_fields.get('function_name', '')} unit={app_fields.get('unit_id', '-')}")
        if app_fields.get("target"):
            findings.append(f"寄存器/线圈目标: {app_fields.get('target', '')}")
        if app_fields.get("exception_code"):
            findings.append(f"设备返回异常码 {app_fields.get('exception_code', '')}，可重点排查失败操作。")
        return findings

    def _render_packet_expert_info(self, detail: dict, risk_value: str, alerts: list[dict]) -> None:
        findings = self._build_expert_findings(detail, risk_value, alerts)
        self._set_text_content(self.packet_expert_text, "\n".join(["Expert Info:"] + [f"- {line}" for line in findings]))

    def _decode_raw_by_mode(self, raw_hex: str, mode: str) -> str:
        m = str(mode or "").strip().lower()
        raw_bytes = decode_raw_bytes(raw_hex)
        if not raw_bytes:
            return "(empty)"
        if m == "ascii":
            text = extract_ascii(raw_bytes)
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
        self._set_text_content(self.packet_detail_text, content)

    def _set_text_content(self, widget: tk.Text, content: str) -> None:
        widget.configure(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.insert("1.0", content)
        widget.configure(state=tk.DISABLED)

    def _insert_detail_tree_nodes(self, tree: ttk.Treeview, parent: str, nodes: list[dict]) -> None:
        for node in nodes:
            item_id = tree.insert(parent, tk.END, text=str(node.get("text", "")), values=(str(node.get("value", "")),))
            self._insert_detail_tree_nodes(tree, item_id, list(node.get("children", [])))
            if bool(node.get("open", False)):
                tree.item(item_id, open=True)

    def _populate_packet_detail_tree(self, tree: ttk.Treeview, detail: dict, risk_value: str, alerts: list[dict]) -> None:
        self._clear_tree(tree)
        self._insert_detail_tree_nodes(tree, "", build_packet_detail_tree_nodes(detail, risk_value, alerts))

    def _render_packet_detail_tree(self, detail: dict, risk_value: str, alerts: list[dict]) -> None:
        self._populate_packet_detail_tree(self.packet_detail_tree, detail, risk_value, alerts)

    def _render_packet_detail(self, detail: dict, values: tuple | list | None = None) -> None:
        row_values = values or ()
        risk_value = row_values[4] if len(row_values) > 4 else str(detail.get("risk_level", "normal"))
        alerts = detail.get("related_alerts", [])
        self._current_packet_detail = detail
        self._render_packet_summary_card(detail, risk_value, alerts)
        self._render_packet_detail_tree(detail, risk_value, alerts)
        self._render_packet_expert_info(detail, risk_value, alerts)
        self._render_current_packet_raw()

    def _load_packet_detail_cached(self, packet_id: int) -> dict | None:
        detail = self._get_cached_packet_detail(packet_id)
        if detail is None:
            detail = self.runtime.query_packet_detail(packet_id)
            if detail:
                self._put_cached_packet_detail(packet_id, detail)
        return detail

    def _render_dialog_packet_detail(
        self,
        tree: ttk.Treeview,
        summary_text: tk.Text,
        expert_text: tk.Text,
        raw_text: tk.Text,
        pos_var: tk.StringVar,
        packet_ids: list[int],
        index: int,
        detail: dict,
        risk_value: str,
        mode: str,
    ) -> None:
        alerts = detail.get("related_alerts", [])
        pos_var.set(build_packet_position_text(packet_ids, index, detail))
        self._set_text_content(summary_text, "\n".join(self._build_packet_summary_lines(detail, risk_value, alerts)))
        self._set_text_content(expert_text, build_expert_info_text(self._build_expert_findings(detail, risk_value, alerts)))
        self._set_text_content(raw_text, self._decode_raw_by_mode(str(detail.get("raw_hex", "")), mode))
        self._populate_packet_detail_tree(tree, detail, risk_value, alerts)

    def open_follow_stream_viewer(self) -> None:
        selected = self.packet_tree.selection()
        if not selected:
            messagebox.showwarning("ERR_INPUT", "请先选择一条流量记录。")
            return
        packet_id = self._packet_tree_db_id(selected[0])
        self._open_flow_view_for_packet_id(packet_id)

    def _show_follow_stream_viewer(self, rows: list[dict], analysis: dict) -> None:
        first = rows[0]
        title = build_flow_window_title(first)
        dlg = tk.Toplevel(self.root)
        self._prepare_detail_dialog(dlg, title, "1380x860", 1080, 700)
        mode_var = tk.StringVar(value="ascii")
        direction_label_var = tk.StringVar(value="双向交错")
        artifact_label_var = tk.StringVar(value="双向交错正文")
        format_var = tk.StringVar(value="txt")
        tip_var = tk.StringVar(value=build_flow_analysis_tip(len(rows), analysis))

        top = ttk.Frame(dlg)
        top.pack(fill=tk.X, padx=8, pady=8)
        self._pack_labeled_combobox(top, "[MODE] Stream编码", mode_var, list(STREAM_MODE_OPTIONS), width=12, combo_padx=6)
        self._pack_labeled_combobox(top, "[DIR] 重组方向", direction_label_var, list(FLOW_DIRECTION_LABEL_MAP.keys()), width=12, label_padx=(8, 0), combo_padx=6)
        artifact_box = self._pack_labeled_combobox(top, "[EXPORT] 导出", artifact_label_var, list(FLOW_ARTIFACT_LABEL_MAP.keys()), width=14, label_padx=(8, 0), combo_padx=6)
        format_box = ttk.Combobox(top, textvariable=format_var, values=artifact_formats("interleaved"), width=10, state="readonly")
        format_box.pack(side=tk.LEFT, padx=6)
        export_btn = self._pack_toolbar_button(top, "[SAVE] 导出", side=tk.RIGHT, padx=0)
        ttk.Label(top, textvariable=tip_var, style="Path.TLabel").pack(side=tk.RIGHT, padx=8)

        body = tk.PanedWindow(dlg, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        stream_panel = ttk.LabelFrame(body, text="[FLOW] 重组流正文", style="Card.TLabelframe")
        stream_panel.columnconfigure(0, weight=1)
        stream_panel.rowconfigure(0, weight=1)
        text = self._grid_scrollable_text_view(stream_panel, row=0, wrap=tk.NONE, pady=4)
        body.add(stream_panel, minsize=760)

        side_panel = ttk.Frame(body)
        side_panel.columnconfigure(0, weight=1)
        side_panel.rowconfigure(1, weight=1)
        ttk.Label(side_panel, text="[INFO] 候选 / 资产 / 对象", style="Hint.TLabel").grid(row=0, column=0, sticky="w", padx=4, pady=(0, 4))
        result_book = ttk.Notebook(side_panel)
        result_book.grid(row=1, column=0, sticky="nsew", padx=4, pady=(0, 4))
        candidate_tree, candidate_detail, _ = self._create_flow_result_tab(
            result_book,
            title="候选",
            columns=[("encoding", "[ENC]", 90), ("source", "[SRC]", 88), ("direction", "[DIR]", 90), ("preview", "[DECODE]", 360)],
            detail_title="[INFO] 候选详情",
        )
        asset_tree, asset_detail, _ = self._create_flow_result_tab(
            result_book,
            title="资产",
            columns=[("type", "[TYPE]", 92), ("direction", "[DIR]", 84), ("name", "[NAME]", 110), ("value", "[VALUE]", 320)],
            detail_title="[INFO] 资产详情",
        )
        object_tree, object_detail, export_object_btn = self._create_flow_result_tab(
            result_book,
            title="对象",
            columns=[("type", "[TYPE]", 92), ("direction", "[DIR]", 84), ("offset", "[OFFSET]", 80), ("size", "[SIZE]", 80), ("preview", "[PREVIEW]", 250)],
            detail_title="[INFO] 对象详情",
            action_button_text="[SAVE] 导出选中对象",
        )
        body.add(side_panel, minsize=520)

        candidate_rows = list(analysis.get("candidates", []))
        asset_rows = list(analysis.get("assets", []))
        object_rows = list(analysis.get("objects", []))
        candidate_index_map: dict[str, int] = {}
        asset_index_map: dict[str, int] = {}
        object_index_map: dict[str, int] = {}

        def render_candidate_detail(_event=None) -> None:
            index = self._tree_selected_index(candidate_tree, candidate_index_map, len(candidate_rows))
            if index < 0:
                return
            self._set_text_content(candidate_detail, candidate_detail_text(candidate_rows[index]))

        def render_asset_detail(_event=None) -> None:
            index = self._tree_selected_index(asset_tree, asset_index_map, len(asset_rows))
            if index < 0:
                return
            self._set_text_content(asset_detail, asset_detail_text(asset_rows[index]))

        def render_object_detail(_event=None) -> None:
            index = self._tree_selected_index(object_tree, object_index_map, len(object_rows))
            if index < 0:
                return
            self._set_text_content(object_detail, object_detail_text(object_rows[index]))

        def export_selected_object() -> None:
            if not object_tree.selection():
                messagebox.showwarning("ERR_DATA", "请先选择要导出的对象。")
                return
            index = self._tree_selected_index(object_tree, object_index_map, len(object_rows))
            if index < 0:
                messagebox.showwarning("ERR_DATA", "对象选择无效。")
                return
            row = object_rows[index]
            suffix = object_export_suffix(str(row.get("object_type", "") or ""))
            output = filedialog.asksaveasfilename(
                title="导出对象",
                defaultextension=suffix,
                filetypes=[("Detected object", f"*{suffix}"), ("All files", "*.*")],
            )
            if not output:
                return
            out_path = self.runtime.export_carved_object(row, Path(output))
            self.runtime.audit.log(
                self.username,
                "object_export",
                str(out_path),
                f"type={row.get('object_type', '')},size={row.get('size', 0)}",
            )
            messagebox.showinfo("OK", f"对象导出成功:\n{out_path}")

        def refresh_artifact_formats(*_args) -> None:
            artifact_key = FLOW_ARTIFACT_LABEL_MAP.get(artifact_label_var.get(), "interleaved")
            formats = artifact_formats(artifact_key)
            format_box.configure(values=formats)
            if format_var.get() not in formats:
                format_var.set(formats[0])

        def render_stream() -> None:
            mode = mode_var.get().strip().lower()
            direction_key = FLOW_DIRECTION_LABEL_MAP.get(direction_label_var.get(), "interleaved")
            content = self.runtime.render_flow_stream_text(
                analysis=analysis,
                mode=mode,
                direction_mode=direction_key,
            )
            self._set_text_content(text, content)

        def export_current() -> None:
            artifact_key = FLOW_ARTIFACT_LABEL_MAP.get(artifact_label_var.get(), "interleaved")
            export_fmt = format_var.get().strip().lower() or "txt"
            ext = ".bin" if export_fmt == "bin" else f".{export_fmt}"
            output = filedialog.asksaveasfilename(
                title="导出会话分析结果",
                defaultextension=ext,
                filetypes=[(f"{export_fmt.upper()} files", f"*{ext}"), ("All files", "*.*")],
            )
            if not output:
                return
            out_path = self.runtime.export_flow_artifact(analysis, Path(output), artifact=artifact_key, file_format=export_fmt)
            self.runtime.audit.log(
                self.username,
                "flow_export",
                str(out_path),
                f"artifact={artifact_key},format={export_fmt},packets={len(rows)}",
            )
            messagebox.showinfo("OK", f"导出成功:\n{out_path}")

        export_btn.configure(command=export_current)
        if export_object_btn is not None:
            export_object_btn.configure(command=export_selected_object)
        mode_var.trace_add("write", lambda *_: render_stream())
        direction_label_var.trace_add("write", lambda *_: render_stream())
        artifact_label_var.trace_add("write", refresh_artifact_formats)
        candidate_tree.bind("<<TreeviewSelect>>", render_candidate_detail)
        asset_tree.bind("<<TreeviewSelect>>", render_asset_detail)
        object_tree.bind("<<TreeviewSelect>>", render_object_detail)
        refresh_artifact_formats()
        self._populate_indexed_tree(candidate_tree, candidate_rows, candidate_index_map, candidate_tree_values, candidate_detail, "当前会话未检测到高置信候选编码串。", render_candidate_detail)
        self._populate_indexed_tree(asset_tree, asset_rows, asset_index_map, asset_tree_values, asset_detail, "当前会话未提取到明显的协议资产。", render_asset_detail)
        self._populate_indexed_tree(object_tree, object_rows, object_index_map, object_tree_values, object_detail, "当前会话未识别到可 carving 的文件对象。", render_object_detail)
        render_stream()
        self._attach_dialog_sizegrip(dlg)

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
        self._reset_packet_view_state(1)
        self._clear_packet_related_views()
        self._reset_packet_panel_texts()
        self._offline_import_done = False
        self._offline_import_error = ""
        mode = self.offline_mode_var.get().strip().lower() or "balanced"
        profile = self.runtime.get_offline_import_profile(mode)
        self.packet_import_status_var.set(self._offline_import_start_status(target.name, profile))
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
            self.packet_progress_var.set(float(progress.get("percent", 0.0)))
            self.packet_import_status_var.set(self._offline_import_progress_status(progress))
        if not self._offline_import_done:
            self.root.after(300, self._poll_offline_import)
            return
        if self._offline_import_error:
            self.packet_import_status_var.set("离线分析状态: 失败")
            messagebox.showerror("ERR_PCAP", self._offline_import_error)
            return
        packets, alerts = self._offline_import_result
        mode = str(self.runtime.offline_progress.get("mode", "balanced"))
        generic_frames = int(self.runtime.offline_progress.get("generic_frames", 0) or 0)
        self.packet_progress_var.set(100.0)
        self.packet_import_status_var.set(self._offline_import_complete_status(mode, packets, generic_frames, alerts))
        file_name = str(self.runtime.offline_progress.get("file", ""))
        self.runtime.audit.log(
            self.username,
            "offline_pcap_import",
            file_name,
            self._offline_import_audit_detail(mode, packets, generic_frames, alerts),
        )
        self.load_packets()
        self.load_alerts()
        messagebox.showinfo("OK", f"离线分析完成：mode={mode}, packets={packets}, frames={generic_frames}, alerts={alerts}")

    def _selected_packet_rows(self) -> list[dict]:
        selected = self.packet_tree.selection()
        if not selected:
            return list(self._packet_rows_in_view[:300])
        ids = [self._packet_tree_db_id(item) for item in selected]
        return self.runtime.query_packets_by_ids(ids)

    def _on_packet_double_click(self, _event=None) -> None:
        if not self._require_admin():
            return
        rows = self._selected_packet_rows()
        if not rows:
            messagebox.showwarning("ERR_INPUT", "没有可导出的流量记录。")
            return
        self._open_export_dialog(rows)

    def open_packet_detail_dialog(self) -> None:
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
        self._prepare_detail_dialog(dlg, "数据包详情", "1320x860", 1080, 700)
        mode_var = tk.StringVar(value="hex")
        pos_var = tk.StringVar(value="")
        rows_by_id = {int(r.get("id", 0) or 0): r for r in self._packet_rows_in_view if int(r.get("id", 0) or 0) > 0}
        bar = ttk.Frame(dlg)
        bar.pack(fill=tk.X, padx=8, pady=8)
        prev_btn = self._pack_toolbar_button(bar, "[PREV] 上一个", padx=(0, 6))
        next_btn = self._pack_toolbar_button(bar, "[NEXT] 下一个", padx=(0, 8))
        self._pack_labeled_combobox(bar, "[ENC] 编码", mode_var, list(PACKET_DETAIL_MODE_OPTIONS), width=12, combo_padx=6)
        ttk.Label(bar, textvariable=pos_var, style="Path.TLabel").pack(side=tk.RIGHT)
        body = tk.PanedWindow(dlg, orient=tk.HORIZONTAL, sashrelief=tk.RAISED, bg="#D1D8E0")
        body.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        left = ttk.LabelFrame(body, text="[TREE] 协议分层", style="Card.TLabelframe")
        left.columnconfigure(0, weight=1)
        left.rowconfigure(0, weight=1)
        tree = self._create_field_value_tree(left)
        body.add(left, minsize=460)

        right = ttk.Frame(body)
        right.columnconfigure(0, weight=1)
        right.rowconfigure(2, weight=1)
        right.rowconfigure(3, weight=3)
        summary_text = self._grid_text_view(right, row=0, height=6, bg="#F0F4F8")
        expert_text = self._grid_text_view(right, row=2, height=4)
        raw_text = self._grid_scrollable_text_view(right, row=3, wrap=tk.NONE)
        body.add(right, minsize=560)

        def render() -> None:
            packet_id = packet_ids[state["index"]]
            detail = self._load_packet_detail_cached(packet_id)
            if not detail:
                return
            row = rows_by_id.get(packet_id, {})
            risk_value = str(row.get("risk_level", detail.get("risk_level", "normal")) or "normal")
            self._render_dialog_packet_detail(tree, summary_text, expert_text, raw_text, pos_var, packet_ids, state["index"], detail, risk_value, mode_var.get().strip().lower())
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
        self._attach_dialog_sizegrip(dlg)

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
        self._set_text_content(self.packet_summary_text, f"流量摘要:\n- 正在生成分析摘要... ID={packet_id}")
        self._set_text_content(self.packet_detail_text, f"正在加载详情... ID={packet_id}")
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
                self._set_text_content(self.packet_detail_text, err if err else "未获取到详情。")
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
        if not self._require_admin():
            return
        dlg = tk.Toplevel(self.root)
        self._prepare_detail_dialog(dlg, "导出捕获流量", "420x220", 360, 200)
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
        self._attach_dialog_sizegrip(dlg)

    def open_packet_batch_export_dialog(self) -> None:
        if not self._require_admin():
            return
        dlg = tk.Toplevel(self.root)
        self._prepare_detail_dialog(dlg, "批量导出与字段提取", "540x360", 480, 320)
        scope_var = tk.StringVar(value="当前筛选全部")
        action_var = tk.StringVar(value="原始流量导出")
        fmt_var = tk.StringVar(value="csv")
        max_rows_var = tk.StringVar(value="20000")
        hint_var = tk.StringVar(value="将对完整筛选命中集执行批量导出，适合做题和取证。")
        for label, variable, values, pady in (
            ("导出范围", scope_var, ["当前选中", "当前页", "当前筛选全部"], (18, 4)),
            ("操作类型", action_var, ["原始流量导出", "字段提取导出", "按流重组导出", "候选字符串导出", "按流正文文件导出"], (12, 4)),
        ):
            ttk.Label(dlg, text=label, style="Hint.TLabel").pack(anchor=tk.W, padx=18, pady=pady)
            ttk.Combobox(dlg, textvariable=variable, values=values, state="readonly", width=24).pack(anchor=tk.W, padx=18)
        line = ttk.Frame(dlg)
        line.pack(fill=tk.X, padx=18, pady=(12, 0))
        fmt_box = self._pack_labeled_combobox(line, "格式", fmt_var, ["csv", "json", "pcap"], width=10, combo_padx=(8, 20))
        self._pack_labeled_entry(line, "最大条数", max_rows_var, width=10, entry_padx=(8, 0), entry_pady=0)
        ttk.Label(dlg, textvariable=hint_var, style="Path.TLabel").pack(fill=tk.X, padx=18, pady=(12, 0), anchor=tk.W)

        def refresh_format_options(*_args) -> None:
            action = action_var.get()
            formats = export_action_formats(action)
            hint_var.set(export_action_hint(action))
            fmt_box.configure(values=formats)
            if fmt_var.get() not in formats:
                fmt_var.set(formats[0])

        def collect_rows(scope_label: str, max_rows: int) -> tuple[list[dict], int, bool]:
            if scope_label == "当前选中":
                selected = self.packet_tree.selection()
                if not selected:
                    raise ValueError("请先选择至少一条流量记录。")
                rows = self.runtime.query_packets_by_ids([self._packet_tree_db_id(item) for item in selected])
                return rows, len(rows), False
            if scope_label == "当前页":
                rows = list(self._packet_rows_in_view)
                return rows, len(rows), False
            result = self.runtime.query_packets_filtered(
                process_name=self.packet_filter_process_var.get().strip(),
                ip=self.packet_filter_ip_var.get().strip(),
                source=self.packet_filter_source_var.get(),
                rule_expr=self.packet_rule_expr_var.get().strip(),
                only_abnormal=self.packet_only_abnormal_var.get(),
                sort_key=self.packet_sort_key_var.get().strip() or "ts",
                sort_desc=self.packet_sort_desc_var.get(),
                max_rows=max_rows,
            )
            return list(result.get("rows", [])), int(result.get("total", 0) or 0), bool(result.get("truncated", False))

        def do_export() -> None:
            try:
                max_rows = max(100, min(200000, int(max_rows_var.get() or 20000)))
            except Exception:
                messagebox.showwarning("ERR_INPUT", "最大条数必须是有效整数。")
                return
            scope_label = scope_var.get().strip()
            action_label = action_var.get().strip()
            fmt = fmt_var.get().strip().lower()
            if action_label == "按流正文文件导出":
                picked_dir = filedialog.askdirectory(title="选择按流正文导出目录")
                output = str(Path(picked_dir) / "flow_bundle") if picked_dir else ""
            else:
                ext = f".{fmt}"
                output = filedialog.asksaveasfilename(
                    title="保存批量导出结果",
                    defaultextension=ext,
                    filetypes=[(f"{fmt.upper()} files", f"*{ext}"), ("All files", "*.*")],
                )
            if not output:
                return
            self.packet_import_status_var.set(build_batch_export_status(scope_label, action_label, fmt))
            result: dict[str, object] = {"error": "", "rows": 0, "total": 0, "truncated": False, "path": None}

            def worker() -> None:
                try:
                    rows, total, truncated = collect_rows(scope_label, max_rows)
                    if not rows:
                        raise ValueError("当前范围内没有可导出的流量记录。")
                    out_path, exported_rows = execute_packet_batch_export(self.runtime, action_label, rows, Path(output), fmt)
                    result["rows"] = exported_rows
                    result["total"] = total
                    result["truncated"] = truncated
                    result["path"] = out_path
                except Exception as exc:
                    result["error"] = str(exc)

            def apply_result() -> None:
                err = str(result.get("error", "") or "").strip()
                if err:
                    self.packet_import_status_var.set("批量导出失败")
                    messagebox.showerror("ERR_EXPORT", err)
                    return
                out_path = result.get("path")
                exported_rows = int(result.get("rows", 0) or 0)
                total = int(result.get("total", exported_rows) or exported_rows)
                truncated = bool(result.get("truncated", False))
                detail = build_batch_export_audit_detail(scope_label, action_label, fmt, exported_rows, total, truncated)
                self.runtime.audit.log(self.username, "packet_batch_export", str(out_path), detail)
                self.packet_import_status_var.set(build_batch_export_status_done(exported_rows, total, truncated))
                messagebox.showinfo("OK", build_batch_export_success_message(Path(str(out_path)), exported_rows, total, truncated))
                dlg.destroy()

            threading.Thread(target=lambda: (worker(), self.root.after(0, apply_result)), daemon=True).start()

        action_var.trace_add("write", refresh_format_options)
        refresh_format_options()
        ttk.Button(dlg, text="[EXEC] 执行批量导出", style="Primary.TButton", command=do_export).pack(pady=22)
        self._attach_dialog_sizegrip(dlg)

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

    def _generate_report(self, source: str, report_title: str) -> None:
        if not self._require_admin():
            return
        report_path = self.runtime.generate_security_report(self.username or "admin", source=source)
        webbrowser.open(report_path.resolve().as_uri())
        messagebox.showinfo("OK", f"{report_title}生成成功:\n{report_path}")

    def generate_realtime_report(self) -> None:
        self._generate_report("live", "实时监测报告")

    def generate_traffic_report(self) -> None:
        self._generate_report("offline", "流量分析报告")

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
        self._set_text_content(self.attack_stats_text, "\n".join(lines))

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
        self._set_text_content(self.attack_desc_text, "\n".join(lines))

    def reset_traffic_display(self) -> None:
        if not self._require_admin():
            return
        self._cancel_packet_render()
        self._packet_load_token += 1
        deleted_packets, deleted_alerts = self.runtime.clear_offline_analysis_data()
        self._packet_rows_in_view = []
        self._packet_tree_id_map.clear()
        self._session_rows_in_view = []
        self._session_tree_id_map.clear()
        self._ctf_clue_rows_in_view = []
        self._ctf_clue_tree_id_map.clear()
        self.packet_filter_source_var.set("offline")
        self.packet_progress_var.set(0.0)
        self._packet_page = 1
        self._packet_total_pages = 1
        self._packet_total_rows = 0
        self._update_packet_page_info()
        self.packet_import_status_var.set("离线分析状态: 空闲")
        self._clear_packet_related_views()
        self._reset_packet_panel_texts()
        self._current_packet_detail = None
        self.runtime.audit.log(self.username, "offline_view_reset", "-", f"deleted_packets={deleted_packets},deleted_alerts={deleted_alerts}")

    def reset_realtime_display(self) -> None:
        if not self._require_admin():
            return
        deleted_packets, deleted_alerts = self.runtime.clear_realtime_monitor_data()
        for i in self.alert_tree.get_children():
            self.alert_tree.delete(i)
        self._reset_alert_panel_texts()
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
        list_type = self.list_type_var.get().strip()
        if list_type == "black":
            ok, msg = self.runtime.upsert_blacklist_with_firewall(
                ip=ip,
                enabled=1,
                remark=self.list_remark_var.get().strip(),
                operator=self.username or "admin",
            )
            if not ok:
                messagebox.showerror("ERR_NET", msg)
                return
        else:
            self.runtime.list_service.upsert(ip, list_type, 1, self.list_remark_var.get().strip())
        self.runtime.audit.log(self.username, "list_upsert", ip, self.list_type_var.get())
        self.list_ip_var.set("")
        self.list_remark_var.set("")
        self.load_list_items()

    def _get_selected_list(self) -> dict | None:
        picked = self.list_tree.selection()
        if not picked:
            return None
        values = self.list_tree.item(picked[0], "values")
        return {
            "id": int(values[0]),
            "ip": str(values[1]),
            "list_type": str(values[2]),
            "enabled": int(values[3]),
            "remark": str(values[4]),
        }

    def toggle_selected_list(self) -> None:
        if not self._require_admin():
            return
        item = self._get_selected_list()
        if not item:
            return
        target_enabled = 0 if item["enabled"] == 1 else 1
        if str(item["list_type"]).strip().lower() == "black":
            ok, msg = self.runtime.update_list_item_with_firewall(
                item_id=int(item["id"]),
                enabled=target_enabled,
                remark=str(item["remark"]),
                operator=self.username or "admin",
            )
            if not ok:
                messagebox.showerror("ERR_NET", msg)
                return
        else:
            self.runtime.list_service.update_item(item["id"], target_enabled, item["remark"])
        self.runtime.audit.log(self.username, "list_update", str(item["id"]), "toggle")
        self.load_list_items()

    def delete_selected_list(self) -> None:
        if not self._require_admin():
            return
        item = self._get_selected_list()
        if not item:
            return
        if str(item["list_type"]).strip().lower() == "black":
            ok, msg = self.runtime.delete_list_item_with_firewall(
                item_id=int(item["id"]),
                operator=self.username or "admin",
            )
            if not ok:
                messagebox.showerror("ERR_NET", msg)
                return
        else:
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
        self.runtime.close()
        self.root.destroy()


def main() -> None:
    app = DesktopApp()
    app.run()


if __name__ == "__main__":
    main()
