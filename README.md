# NetScope 流量安全检测分析系统

## 快速开始

```bash
cd e:\SP

# 1. 安装生产依赖
python -m pip install -r requirements.txt

# 2. 训练模型（首次运行或模型不存在时）
python scripts/train_model.py

# 3. 启动桌面版
python desktop_main.py

# 4. 测试运行
python -m pip install -r requirements-test.txt
python -m pytest tests/ -q
```

## 环境要求

- Windows 10/11 64 位
- Anaconda / Miniconda（推荐 Python 3.12+）
- pydivert 可用（依赖 WinDivert 驱动）
- 如离线解析走原生模式，需编译 `traffic_core.pyd`：`powershell -ExecutionPolicy Bypass -File scripts/build_traffic_core.ps1`

## 默认账号

| 角色 | 用户名 | 密码 |
|------|--------|------|
| 管理员 | `admin` | `Admin@123456` |
| 只读用户 | `user` | `User@123456` |

> 初始密码仅用于首次登录：系统会强制要求修改密码，设置新密码后才可进入主界面。

## 功能概览

### 实时流量监测
- 基于 WinDivert/pydivert 的 Windows 层包嗅探
- 进程级网络归因（通过 psutil 连接表将流量映射到 PID 和进程名）
- 会话聚合（按 5 元组 + 方向构建流统计，提取 30+ 检测特征）
- 三重检测：规则引擎 + Isolation Forest ML 模型 + 黑白名单
- 桌面通知（高危告警推送，45 秒去重）

### 检测能力（22 种攻击类型）
| 类别 | 攻击类型 |
|------|----------|
| 拒绝服务攻击 | SYN Flood、UDP Flood、ICMP Flood |
| 暴力破解 | SSH、RDP、数据库、FTP、Web |
| 横向移动 | 内网扫描、SMB/RDP 异常访问 |
| 端口与服务 | 端口扫描、服务探测 |
| 命令控制 | C&C 通信、DNS 隧道、ICMP 隧道、反向 Shell |
| 数据泄露 | 异常大数据传输、敏感端口访问 |
| Web 攻击 | SQL 注入、XSS、目录遍历 |
| 连接异常 | 异常长会话、异常短请求间隔 |

### 离线流量分析
- 支持 PCAP/PCAPNG 文件导入，5GB+ 大文件流式解析
- 四种模式：Speed（最快）/ Balanced（均衡）/ Detect（检测）/ Extreme（极限）
- 原生 C++ 解析（pybind11 + traffic_core.pyd）优先，Scapy 回退
- DuckDB 列式存储海量包明细，Arrow 批量写入
- 通用帧查看（hex/ascii/utf-8/base64 多编码）
- 包过滤引擎（类 Wireshark 表达式：IP/端口/协议/进程名/方向）
- 批量导出：字段提取、按流重组正文、候选字符串导出（base32/64/hex/url 二次解码链）

### CTF 取证工作台
- TCP 流重组与双向交错分析
- 文件雕刻（PNG/ZIP/GZIP/PDF/JPEG/GIF/PE/ELF 签名扫描）
- USB HID 键盘流量解析（键码→字符映射）
- 线索构建：敏感端口、可疑进程、异常外联、DNS 查询、Modbus 工控协议
- 风险评分与取证摘要

### 主动防御
- 黑名单 IP ↔ Windows 防火墙双向同步
- 告警页一键封禁源 IP（入站/出站双向防火墙规则）
- 隐私追踪拦截（识别 Google Analytics、Facebook、Mixpanel 等 13 个追踪域名）

### 安全审计与报告
- 审计日志（操作类型、目标、详情），30 天自动清理
- HTML 安全报告生成（告警汇总、流量趋势、风险分布、异常 IP 排行）

## 项目架构

```
src/
├── config.py                   # 全局配置 (AppConfig dataclass)
├── subprocess_utils.py         # 子进程调用工具
├── desktop_main.py             # PySide6 桌面应用入口
├── app/                        # 应用运行时层
│   ├── runtime.py              # AppRuntime 核心调度引擎
│   ├── offline_imports.py      # 离线 PCAP 导入编排
│   ├── packet_queries.py       # 包查询分页/过滤
│   └── packet_batch_exports.py # 批量导出业务层
└── core/                       # 核心功能模块
    ├── packet_inspection.py    # 包解析（HTTP/DNS/TLS/Modbus 字段提取）
    ├── packet_detail_view.py   # 包详情视图（分层协议树 + 专家信息）
    ├── flow_view_models.py     # 流视图数据模型
    ├── frame_intel.py          # 帧情报（USB HID 键码等）
    ├── aggregation/            # 会话聚合器（5元组流统计 + 特征提取）
    ├── audit/                  # 审计服务
    ├── auth/                   # 认证服务（PBKDF2-SHA256）
    ├── capture/                # 抓包引擎（WinDivert/pydivert）
    ├── ctf/                    # CTF 取证（流重组/文件雕刻/线索构建/批量导出）
    ├── detection/              # 检测服务（规则引擎 + ML 模型 + 知识库）
    ├── filtering/              # 包过滤规则引擎
    ├── notify/                 # 桌面通知服务
    ├── offline/                # 离线 PCAP 解析适配器
    ├── report/                 # HTML 安全报告生成
    ├── storage/                # 持久化（SQLite 事务 + DuckDB 离线明细）
    └── whitelist_blacklist/    # 黑白名单 + 隐私追踪
```

## 数据库架构

采用"按场景分层"双库策略：

| 数据库 | 引擎 | 用途 |
|--------|------|------|
| `data/system.db` | SQLite (WAL) | 告警、审计、认证、黑白名单、实时统计、流风险摘要 |
| `data/offline_packets.duckdb` | DuckDB | 离线大包明细（packets + frames），Arrow 列式批量写入 |

## 测试体系

- 17 个测试文件，173 条用例（单元 ~119 + 集成 ~38 + 安全 22 + 性能 11 + CTF ~35）
- pytest.ini 定义 9 种标记：`unit` / `integration` / `api` / `performance` / `security` / `slow` / `ctf` / `detection` / `capture` / `offline`
- conftest.py 提供共享 fixtures：`tmp_db`、`sample_packet`、`mock_runtime` 等
- 覆盖率目标 ≥50%（当前 ~51.8%），质量门禁：单元覆盖 ≥60%、集成通过率 ≥95%、高危漏洞 = 0

```bash
# 按分层运行
python -m pytest tests/ -m unit          # 单元测试
python -m pytest tests/ -m integration   # 集成测试
python -m pytest tests/ -m security      # 安全测试
python -m pytest tests/ -m performance   # 性能基准

# 覆盖率报告
python -m coverage run -m pytest tests/
python -m coverage html --include="src/**" -d test_results/htmlcov

# Lint 与安全扫描
ruff check src/ tests/
bandit -r src/
```

## CI 流水线

`.github/workflows/ci.yml` 五阶段流水线：

1. **Lint** — ruff 静态分析
2. **安全** — bandit 安全扫描
3. **单元** — pytest + coverage（门禁 50%）
4. **集成** — 跨模块集成测试
5. **性能** — 基准回归（衰退容忍度 ≤5%）

## 打包

```bash
powershell -ExecutionPolicy Bypass -File scripts/build_exe.ps1
```

输出：`exe/ai_traffic_guard_desktop.exe`

## 目录说明

| 目录 | 说明 |
|------|------|
| `src/` | 系统源代码 |
| `tests/` | 测试用例（含 conftest.py 共享 fixtures） |
| `scripts/` | 训练、打包、编译、基准测试脚本 |
| `models/` | 预训练 Isolation Forest 模型（`iforest_model.joblib`） |
| `data/` | SQLite 数据库与 DuckDB 离线存储 |
| `native/traffic_core/` | C++ 原生解析模块（pybind11 绑定） |
| `docs/` | 文档交付物 |
| `.github/workflows/` | CI 流水线定义 |

## 日志策略

- 系统自动清理 30 天前日志（alerts / audit_logs / traffic_stats）
- 管理员可在桌面版"审计日志"页执行删除与批量删除

## License

[MIT](LICENSE) © 2026 xiaoren
