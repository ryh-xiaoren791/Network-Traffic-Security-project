# SP 测试套件

## 快速重跑

```bash
cd e:\SP

# 安装依赖
python -m pip install -r requirements.txt
python -m pip install -r requirements-test.txt

# 运行全部测试
python -m pytest tests/

# 按分层运行
python -m pytest tests/ -m unit                # 单元测试
python -m pytest tests/ -m integration         # 集成测试
python -m pytest tests/ -m performance         # 性能测试
python -m pytest tests/ -m security            # 安全测试
python -m pytest tests/ -m api                 # 接口契约测试

# 覆盖率
python -m coverage run -m pytest tests/
python -m coverage report --include="src/**"
python -m coverage html --include="src/**" -d reports/coverage_html
```

## 分层测试策略

| 层级 | 标记 | 文件 | 用例数 | 入口准则 | 完成准则 |
|------|------|------|--------|----------|----------|
| **单元测试** | `unit` | test_core, test_packet_*, test_ctf_*, test_flow_*, test_frame_*, test_offline_adapter, test_benchmark_guard | ~119 | 纯函数/类方法，无外部IO | 覆盖率≥60% |
| **集成测试** | `integration` | test_integration.py, test_runtime_flow_workbench.py, test_offline_imports.py | ~38 | 多模块协作，DB/mock | 通过率≥95% |
| **接口测试** | `api` | test_integration.py (部分) | ~5 | AppRuntime 公开API | 通过率≥95% |
| **性能测试** | `performance` | test_performance.py | 11 | 关键路径基准回归 | 性能衰退≤5% |
| **安全测试** | `security` | test_security.py | 22 | SQL注入/认证/输入 | 高危漏洞=0 |
| **CTF专项** | `ctf` | test_ctf_clues, test_ctf_service, test_packet_batch_export* | ~35 | CTF取证功能 | 通过率100% |
| **检测专项** | `detection` | test_core (检测部分) | ~10 | 检测流水线 | 通过率100% |

## 测试基础设施

```
tests/
├── conftest.py              # 共享fixtures: tmp_db, sample_packet, mock_runtime
├── test_core.py             # 核心功能全覆盖 (DB/检测/抓包/聚合/认证/通知)
├── test_integration.py      # 跨模块集成测试 (DB+Detection, Auth+Audit等)
├── test_performance.py      # 性能基准回归 (哈希/DB/检测/聚合/解析)
├── test_security.py         # 安全测试 (SQL注入/认证绕过/输入校验)
├── test_ctf_service.py      # CTF流分析服务
├── test_ctf_clues.py        # CTF线索构建
├── test_packet_batch_export.py   # 批量导出服务
├── test_packet_batch_exports.py  # 批量导出业务层
├── test_packet_inspection.py     # 包解析
├── test_packet_rules.py          # 包过滤规则
├── test_packet_detail_view.py    # 包详情视图
├── test_flow_view_models.py      # 流视图模型
├── test_frame_intel.py           # 帧情报
├── test_offline_imports.py       # 离线导入
├── test_offline_adapter.py       # 离线适配层
├── test_runtime_flow_workbench.py # 运行时流工作台
├── test_benchmark_guard.py       # 基准守护
└── README.md                 # 本文件
```

## 质量门禁

| 指标 | 目标 | 当前值 | 门禁 |
|------|------|--------|------|
| 单元测试覆盖率 | ≥60% | 55% (stmt) / 52% (branch) | CI fail-under=50% |
| 集成/接口通过率 | ≥95% | 100% | CI 阻塞 |
| 性能衰退 | ≤5% | 基准已建立 | 需手动对比 |
| 高危安全漏洞 | 0 | 待bandit扫描 | CI 阻塞 |

## CI 流水线

`.github/workflows/ci.yml` 包含4个阶段：

1. **lint** - ruff 静态分析
2. **security** - bandit 安全扫描
3. **unit** - 单元+集成测试 + 覆盖率 (需 lint 通过)
4. **integration** - 集成+接口测试 (需 unit 通过)
5. **performance** - 性能基准测试 (需 integration 通过)

## 测试数据

- 使用 `tmp_path` fixture，所有数据库/文件操作隔离到临时目录
- 无需外部测试数据文件
- 如需真实 PCAP 测试，将 pcap 文件放入 `data/` 目录并在测试中引用
