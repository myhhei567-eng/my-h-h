"""
AWS Multi-Agent 智能运维巡检系统 - 主入口
支持 CLI 和 Web Dashboard 两种运行模式
"""
import sys
import os
import json
import yaml
import argparse

# 确保项目根目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.orchestrator import Orchestrator
from mock.mock_aws import generate_mock_resources


def load_config(path="config.yaml"):
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), path)
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def run_cli(config):
    """CLI 模式运行"""
    print("\n🚀 AWS Multi-Agent 智能运维巡检系统")
    print("=" * 60)
    print(f"   运行模式: {config.get('mode', 'mock').upper()}")
    print(f"   区域: {config.get('aws', {}).get('region', 'N/A')}")
    print("=" * 60)

    resources = generate_mock_resources() if config.get("mode") == "mock" else []
    orchestrator = Orchestrator(config, resources)
    report = orchestrator.run()

    # 输出详细报告
    print("\n\n" + "=" * 60)
    print("📋 详细安全发现")
    print("=" * 60)
    for i, f in enumerate(report.findings):
        icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f.severity.value, "⚪")
        print(f"\n  {icon} [{f.severity.value}] {f.rule_id}: {f.rule_name}")
        print(f"     资源: {f.resource.name} ({f.resource.resource_id})")
        print(f"     详情: {f.details}")

    print("\n\n" + "=" * 60)
    print("🧠 根因分析摘要")
    print("=" * 60)
    for a in report.analyses:
        if a.finding:
            print(f"\n  [{a.finding.rule_id}] 风险评分: {a.risk_score}/100")
            print(f"  根因: {a.root_cause}")
            print(f"  影响: {a.impact_assessment}")
            print(f"  建议: {a.recommendation}")

    print("\n\n" + "=" * 60)
    print("🔧 修复计划")
    print("=" * 60)
    for p in report.remediation_plans:
        if p.analysis and p.analysis.finding:
            status_icon = "✅" if p.status.value == "generated" else "⏳"
            print(f"\n  {status_icon} {p.description}")
            print(f"     状态: {p.status.value} | 风险等级: {p.estimated_risk}")
            print(f"     步骤:")
            for j, s in enumerate(p.steps):
                print(f"       {j+1}. {s}")
            if p.cfn_template:
                print(f"     [CloudFormation模板已生成 ✓]")

    # 保存报告到 JSON
    output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")
    os.makedirs(output_dir, exist_ok=True)
    report_path = os.path.join(output_dir, f"report_{report.report_id}.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
    print(f"\n📁 完整报告已保存: {report_path}")

    return report


def run_dashboard(config):
    """Web Dashboard 模式运行"""
    from dashboard import create_app
    resources = generate_mock_resources() if config.get("mode") == "mock" else []
    app = create_app(config, resources)
    host = config.get("dashboard", {}).get("host", "127.0.0.1")
    port = config.get("dashboard", {}).get("port", 5000)
    print(f"\n🌐 Dashboard 启动: http://{host}:{port}")
    app.run(host=host, port=port, debug=True)


def main():
    parser = argparse.ArgumentParser(description="AWS Multi-Agent 智能运维巡检系统")
    parser.add_argument("--mode", choices=["cli", "web"], default="cli", help="运行模式: cli(命令行) 或 web(Dashboard)")
    parser.add_argument("--config", default="config.yaml", help="配置文件路径")
    args = parser.parse_args()

    config = load_config(args.config)

    if args.mode == "cli":
        run_cli(config)
    else:
        run_dashboard(config)


if __name__ == "__main__":
    main()
