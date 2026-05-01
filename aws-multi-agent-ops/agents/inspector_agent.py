"""
巡检 Agent
负责扫描 AWS 资源并检测安全问题
"""
from typing import List
from agents.base_agent import BaseAgent
from tools.aws_scanner import AWSScanner
from tools.security_checker import SecurityChecker
from core.models import AWSResource, SecurityFinding, AgentStatus


class InspectorAgent(BaseAgent):
    def __init__(self, scanner: AWSScanner, checker: SecurityChecker):
        super().__init__("InspectorAgent", "巡检Agent - 扫描AWS资源配置合规性和安全漏洞")
        self.scanner = scanner
        self.checker = checker
        # 注册工具
        self.engine.register_tool("scan_resources", self._tool_scan, "扫描AWS资源")
        self.engine.register_tool("check_security", self._tool_check, "检查安全合规")

    def _tool_scan(self, resource_type: str = None) -> str:
        if resource_type:
            resources = self.scanner.scan_by_type(resource_type)
        else:
            resources = self.scanner.scan_all()
            self._all_resources = list(resources)
        self._scanned = resources
        return f"扫描到 {len(resources)} 个资源"

    def _tool_check(self, **kwargs) -> str:
        self._findings = self.checker.check_all(self._all_resources)
        return f"发现 {len(self._findings)} 个安全问题"

    def run(self, context: dict) -> dict:
        self.status = AgentStatus.THINKING
        self.engine.reset()
        self._scanned: List[AWSResource] = []
        self._findings: List[SecurityFinding] = []

        # Step 1: 扫描所有资源
        self.engine.run_step(
            thought="开始全面扫描AWS环境中的所有资源，包括EC2、S3、RDS、安全组和IAM用户",
            action="scan_resources",
        )

        # Step 2: 按类型逐一深度扫描
        for rt in ["ec2", "s3", "rds", "security_group", "iam"]:
            self.engine.run_step(
                thought=f"对 {rt.upper()} 类型资源进行深度配置扫描",
                action="scan_resources",
                action_input={"resource_type": rt},
            )

        # Step 3: 执行安全规则检查
        self.engine.run_step(
            thought="对所有扫描到的资源执行安全规则检查，包括加密、公开访问、权限等维度",
            action="check_security",
        )

        # Step 4: 汇总
        self.engine.run_step(
            thought=f"巡检完成。共扫描 {len(self._scanned)} 个资源，发现 {len(self._findings)} 个安全问题。"
                    f"其中 CRITICAL: {sum(1 for f in self._findings if f.severity.value=='CRITICAL')}, "
                    f"HIGH: {sum(1 for f in self._findings if f.severity.value=='HIGH')}, "
                    f"MEDIUM: {sum(1 for f in self._findings if f.severity.value=='MEDIUM')}, "
                    f"LOW: {sum(1 for f in self._findings if f.severity.value=='LOW')}",
            action="scan_resources",  # 最终确认
        )

        self.status = AgentStatus.COMPLETED
        context["resources"] = self._scanned
        context["findings"] = self._findings
        context["inspector_reasoning"] = self.engine.get_reasoning_chain()
        return context
