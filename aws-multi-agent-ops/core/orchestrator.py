"""
Multi-Agent 编排器
协调三个 Agent 的执行顺序和数据流转
"""
import time
from typing import Dict, Any, List
from core.models import InspectionReport
from agents.inspector_agent import InspectorAgent
from agents.analyzer_agent import AnalyzerAgent
from agents.remediation_agent import RemediationAgent
from tools.aws_scanner import AWSScanner
from tools.security_checker import SecurityChecker


class Orchestrator:
    def __init__(self, config: dict, resources=None):
        mode = config.get("mode", "mock")
        region = config.get("aws", {}).get("region", "ap-northeast-1")
        rules = config.get("security_rules", {})

        self.scanner = AWSScanner(mode=mode, region=region)
        self.checker = SecurityChecker(rules=rules)

        if resources:
            self.scanner.load_resources(resources)

        self.inspector = InspectorAgent(self.scanner, self.checker)
        self.analyzer = AnalyzerAgent()
        self.remediation = RemediationAgent()

    def run(self) -> InspectionReport:
        """执行完整的巡检流程: 巡检 -> 分析 -> 修复"""
        start = time.time()
        context: Dict[str, Any] = {}

        print("\n" + "=" * 60)
        print("🔍 [1/3] InspectorAgent 开始巡检...")
        print("=" * 60)
        context = self.inspector.run(context)
        findings = context.get("findings", [])
        print(f"   ✅ 巡检完成: 发现 {len(findings)} 个安全问题")

        print("\n" + "=" * 60)
        print("🧠 [2/3] AnalyzerAgent 开始根因分析...")
        print("=" * 60)
        context = self.analyzer.run(context)
        analyses = context.get("analyses", [])
        print(f"   ✅ 分析完成: 生成 {len(analyses)} 个根因分析报告")

        print("\n" + "=" * 60)
        print("🔧 [3/3] RemediationAgent 生成修复方案...")
        print("=" * 60)
        context = self.remediation.run(context)
        plans = context.get("remediation_plans", [])
        print(f"   ✅ 修复方案完成: 生成 {len(plans)} 个修复计划")

        duration = time.time() - start

        # 汇总所有日志
        all_logs = (self.inspector.get_logs() +
                    self.analyzer.get_logs() +
                    self.remediation.get_logs())

        report = InspectionReport(
            resources_scanned=len(context.get("resources", [])),
            findings=findings,
            analyses=analyses,
            remediation_plans=plans,
            total_duration_seconds=round(duration, 2),
            agent_logs=all_logs,
        )

        print("\n" + "=" * 60)
        print(f"📊 巡检报告 (ID: {report.report_id})")
        print(f"   扫描资源: {report.resources_scanned}")
        print(f"   安全评分: {report.overall_score}/100")
        print(f"   CRITICAL: {report.critical_count} | HIGH: {report.high_count} | "
              f"MEDIUM: {report.medium_count} | LOW: {report.low_count}")
        print(f"   耗时: {report.total_duration_seconds}s")
        print("=" * 60)

        return report
