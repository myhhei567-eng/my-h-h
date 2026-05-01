# AWS Multi-Agent 智能运维巡检系统

基于 **ReAct 推理框架** 和 **多 Agent 协作** 的 AWS 智能运维巡检系统。

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌──────────────────┐
│ InspectorAgent  │───→│  AnalyzerAgent  │───→│ RemediationAgent │
│  (巡检Agent)    │    │  (分析Agent)     │    │  (修复Agent)      │
│                 │    │                 │    │                  │
│ • 扫描AWS资源   │    │ • 长链推理       │    │ • 生成CFN模板     │
│ • 检测安全漏洞  │    │ • 根因定位       │    │ • 自动修复方案    │
│ • 合规性检查    │    │ • 影响评估       │    │ • 回滚计划       │
└─────────────────┘    └─────────────────┘    └──────────────────┘
         │                     │                       │
         └─────────────────────┴───────────────────────┘
                          ReAct Engine
                   (Thought → Action → Observation)
```

## 核心特性

- **三个协作 Agent**: 巡检、分析、修复，形成完整闭环
- **ReAct 推理框架**: 每个 Agent 通过 思考→行动→观察 循环推理
- **15+ 安全规则**: 覆盖 EC2/S3/RDS/安全组/IAM 五大资源类型
- **自动生成 CloudFormation 修复模板**: 8 种问题可自动生成修复模板
- **Mock 模式**: 无需 AWS 凭证即可演示完整流程
- **Web Dashboard**: 可视化巡检报告和推理链

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. CLI 模式运行

```bash
python main.py --mode cli
```

### 3. Web Dashboard 模式

```bash
python main.py --mode web
```

然后访问 http://127.0.0.1:5000

## 检测规则

| 规则ID | 名称 | 严重程度 |
|--------|------|----------|
| EC2-001 | EC2实例未加密EBS卷 | HIGH |
| EC2-002 | EC2实例使用默认安全组 | MEDIUM |
| EC2-003 | EC2实例无IAM角色 | MEDIUM |
| S3-001 | S3存储桶公开访问 | CRITICAL |
| S3-002 | S3存储桶未启用版本控制 | LOW |
| S3-003 | S3存储桶未启用加密 | HIGH |
| RDS-001 | RDS实例公开可访问 | CRITICAL |
| RDS-002 | RDS实例未启用多可用区 | MEDIUM |
| RDS-003 | RDS实例未启用自动备份 | HIGH |
| SG-001 | 安全组全端口开放 | CRITICAL |
| SG-002 | SSH对全网开放 | HIGH |
| SG-003 | RDP对全网开放 | HIGH |
| IAM-001 | IAM用户未启用MFA | HIGH |
| IAM-002 | IAM用户拥有Admin权限 | CRITICAL |

## 项目结构

```
aws-multi-agent-ops/
├── main.py              # 主入口 (CLI/Web)
├── dashboard.py         # Flask Web Dashboard
├── config.yaml          # 系统配置和安全规则
├── requirements.txt     # Python 依赖
├── agents/              # Agent 层
│   ├── base_agent.py        # 基础Agent抽象类
│   ├── inspector_agent.py   # 巡检Agent
│   ├── analyzer_agent.py    # 分析Agent(含根因知识库)
│   └── remediation_agent.py # 修复Agent
├── core/                # 核心引擎
│   ├── models.py            # 数据模型
│   ├── react_engine.py      # ReAct推理引擎
│   └── orchestrator.py      # Multi-Agent编排器
├── tools/               # 工具层
│   ├── aws_scanner.py       # AWS资源扫描器
│   ├── security_checker.py  # 安全规则检查器
│   └── cfn_generator.py     # CloudFormation模板生成器
├── mock/                # 模拟数据
│   └── mock_aws.py          # Mock AWS资源(含安全隐患)
└── templates/           # Web模板
    └── dashboard.html       # Dashboard页面
```

## 技术栈

- Python 3.8+
- Flask (Web Dashboard)
- boto3 (AWS SDK, live模式)
- PyYAML (配置解析)
- ReAct 推理框架
