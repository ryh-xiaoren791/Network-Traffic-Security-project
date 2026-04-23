ATTACK_KNOWLEDGE: dict[str, dict[str, str]] = {
    "SYN Flood攻击": {
        "type": "拒绝服务攻击类",
        "level": "high",
        "description": "大量SYN请求快速占用服务端半连接队列，造成合法请求超时。",
        "mitigation": "启用SYN Cookie、限速并结合防火墙封禁异常源地址。",
    },
    "UDP Flood攻击": {
        "type": "拒绝服务攻击类",
        "level": "high",
        "description": "异常高频UDP流量持续冲击目标端口与带宽资源。",
        "mitigation": "对UDP业务做速率限制，收敛暴露端口并启用ACL。",
    },
    "ICMP Flood攻击": {
        "type": "拒绝服务攻击类",
        "level": "high",
        "description": "大量ICMP报文导致链路与处理资源被快速消耗。",
        "mitigation": "限制ICMP速率并在边界设备设置流量清洗策略。",
    },
    "SSH暴力破解": {
        "type": "暴力破解类",
        "level": "high",
        "description": "短时间内对SSH端口持续发起高频认证尝试。",
        "mitigation": "启用MFA、失败锁定与IP封禁，避免弱口令。",
    },
    "RDP暴力破解": {
        "type": "暴力破解类",
        "level": "high",
        "description": "RDP服务出现异常高频连接与认证探测行为。",
        "mitigation": "限制源IP访问、启用NLA与强密码策略。",
    },
    "数据库暴力破解": {
        "type": "暴力破解类",
        "level": "high",
        "description": "数据库端口出现异常高频登录尝试与连接重试。",
        "mitigation": "数据库仅内网开放，启用账号锁定与访问白名单。",
    },
    "FTP暴力破解": {
        "type": "暴力破解类",
        "level": "medium",
        "description": "FTP端口持续高频连接，疑似口令枚举。",
        "mitigation": "关闭明文FTP或迁移SFTP，启用失败惩罚机制。",
    },
    "Web暴力破解": {
        "type": "暴力破解类",
        "level": "medium",
        "description": "Web登录接口被高频访问且成功率偏低。",
        "mitigation": "增加验证码、限流与WAF规则，审计登录日志。",
    },
    "内网扫描行为": {
        "type": "横向移动类",
        "level": "high",
        "description": "单源在短时间访问大量内网地址，疑似资产探测。",
        "mitigation": "分区隔离内网网段，监控并阻断异常扫描主机。",
    },
    "服务探测行为": {
        "type": "端口与服务类",
        "level": "medium",
        "description": "频繁探测常见服务端口，疑似服务枚举。",
        "mitigation": "最小化暴露端口，设置扫描告警与自动封禁。",
    },
    "端口扫描行为": {
        "type": "端口与服务类",
        "level": "high",
        "description": "5秒窗口内访问端口数量显著异常。",
        "mitigation": "启用端口敲门或ACL，限制未知来源探测。",
    },
    "反向Shell可疑": {
        "type": "命令控制类",
        "level": "high",
        "description": "外连高端口且会话持续，行为接近反向控制通道。",
        "mitigation": "立即隔离主机并排查启动项、计划任务与恶意进程。",
    },
    "C&C通信可疑": {
        "type": "命令控制类",
        "level": "high",
        "description": "请求间隔高度周期化，疑似与控制端心跳通信。",
        "mitigation": "阻断外联目标并关联DNS、进程与文件取证。",
    },
    "DNS隧道可疑": {
        "type": "命令控制类",
        "level": "high",
        "description": "DNS流量异常高频且负载偏大，疑似隧道传输。",
        "mitigation": "限制外部DNS访问，仅允许企业递归DNS出口。",
    },
    "ICMP隧道可疑": {
        "type": "命令控制类",
        "level": "high",
        "description": "ICMP报文大小与频率异常，疑似隐蔽隧道。",
        "mitigation": "收紧ICMP策略并排查异常端点主机。",
    },
    "SMB/RDP异常访问": {
        "type": "横向移动类",
        "level": "high",
        "description": "内网源对SMB/RDP目标出现异常连接爆发。",
        "mitigation": "执行横向移动阻断策略并核查管理员凭据泄露。",
    },
    "异常大数据传输": {
        "type": "数据泄露类",
        "level": "high",
        "description": "长会话内出现明显超常的大流量传输。",
        "mitigation": "核验业务合法性并对可疑主机做数据外发审计。",
    },
    "敏感端口访问": {
        "type": "数据泄露类",
        "level": "high",
        "description": "外连敏感端口并伴随较大数据量，存在泄露风险。",
        "mitigation": "阻断目标端口外联并审查传输内容与目的地。",
    },
    "SQL注入攻击": {
        "type": "Web攻击类",
        "level": "high",
        "description": "HTTP负载出现典型SQL关键字组合与注入特征。",
        "mitigation": "启用参数化查询、WAF拦截与输入校验。",
    },
    "XSS攻击": {
        "type": "Web攻击类",
        "level": "medium",
        "description": "请求负载包含脚本注入特征，可能触发XSS。",
        "mitigation": "输出编码、CSP策略与输入过滤并行启用。",
    },
    "目录遍历攻击": {
        "type": "Web攻击类",
        "level": "medium",
        "description": "URL或参数包含目录穿越模式，尝试越权访问文件。",
        "mitigation": "规范化路径并限制文件访问根目录。",
    },
    "异常长会话": {
        "type": "连接异常类",
        "level": "medium",
        "description": "会话持续时间显著偏长，存在隐蔽通道风险。",
        "mitigation": "结合进程与目标域名进一步核验会话用途。",
    },
    "异常短请求间隔": {
        "type": "连接异常类",
        "level": "medium",
        "description": "请求间隔极短且重复，疑似自动化攻击脚本。",
        "mitigation": "启用频率限制和行为验证码，追踪源主机。",
    },
}


def get_attack_knowledge(sub_category: str) -> dict[str, str]:
    return ATTACK_KNOWLEDGE.get(
        sub_category,
        {
            "type": "访问与流量类",
            "level": "low",
            "description": "检测到可疑流量特征，请结合上下文进一步分析。",
            "mitigation": "核验来源进程与通信目标，必要时执行隔离与封禁。",
        },
    )
