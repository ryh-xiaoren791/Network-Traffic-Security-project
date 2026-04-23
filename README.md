# 基于AI的Windows终端流量异常检测系统

## 快速开始
1. 安装依赖：`python -m pip install -r requirements.txt`
2. 训练模型：`python scripts/train_model.py`
3. 启动桌面版：`python desktop_main.py`
4. 桌面版流程：先登录/注册，再进入功能工作台
5. 管理员可在告警页执行“一键封禁源IP”触发Windows防火墙规则

## 环境要求
- Windows 11 64位
- pydivert可用（依赖WinDivert驱动）

## 默认账号
- 管理员：`admin`
- 密码：`Admin@123456`
- 普通用户：`user`
- 密码：`User@123456`

## 个人版新增能力
- 应用级网络归因：采集阶段尝试将连接映射到进程PID与进程名
- 一键主动防御：支持对选中告警源IP执行防火墙入站/出站双向封禁
- 隐私追踪拦截：通过反向DNS识别常见追踪域名并生成防护告警
- 安全评分看板：新增隐私拦截统计与设备安全评分

## 日志策略
- 系统自动清理30天前日志（alerts/audit_logs/traffic_stats）
- 管理员可在桌面版“审计日志”页执行删除选中与按过滤批量删除

## 打包
- 执行：`powershell -ExecutionPolicy Bypass -File scripts/build_exe.ps1`
- 输出：`exe/ai_traffic_guard_desktop.exe`

## 目录
- docs：文档交付物
- ppt：PPT源文件（Marp）
- src：系统源代码
- models：预训练模型
- data：SQLite数据库
- tests：测试用例
- scripts：训练与打包脚本

## 数据库架构说明
- 当前采用“按场景分层”：
- `DuckDB` 仅用于离线大包明细（性能热点）。
- `SQLite` 继续用于告警、审计、认证、白黑名单、实时统计等事务数据。
- 详细边界与迁移优先级见 [数据库边界与迁移优先级](docs/数据库边界与迁移优先级.md)。
