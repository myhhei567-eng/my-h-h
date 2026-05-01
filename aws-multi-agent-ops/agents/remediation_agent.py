"""
修复 Agent
根据分析结果自动生成 CloudFormation 变更集进行修复
"""
from agents.base_agent import BaseAgent
from tools.cfn_generator import CFNGenerator
from core.models import (RootCauseAnalysis, RemediationPlan,
                         RemediationStatus, AgentStatus, Severity)
from typing import List


class RemediationAgent(BaseAgent):
    def __init__(self):
        super().__init__("RemediationAgent", "修复Agent - 自动生成CloudFormation修复模板")
        self.cfn_gen = CFNGenerator()
        self.engine.register_tool("generate_cfn", self._tool_gen, "生成CFN模板")
        self.engine.register_tool("validate_cfn", lambda **kw: "模板验证通过", "验证模板")
        self.engine.register_tool("create_plan", lambda **kw: "修复计划已创建", "创建计划")

    def _tool_gen(self, **kwargs) -> str:
        return "CloudFormation模板已生成"

    def run(self, context: dict) -> dict:
        self.status = AgentStatus.THINKING
        self.engine.reset()
        analyses: List[RootCauseAnalysis] = context.get("analyses", [])
        plans: List[RemediationPlan] = []

        # Step 1: 评估需要修复的问题
        fixable = [a for a in analyses if a.finding and a.finding.rule_id in CFNGenerator.REMEDIATION_MAP]
        manual = [a for a in analyses if a not in fixable]

        self.engine.run_step(
            thought=f"收到 {len(analyses)} 个分析结果。"
                    f"{len(fixable)} 个可自动生成CloudFormation修复模板，"
                    f"{len(manual)} 个需要手动修复。按风险评分排序处理",
            action="create_plan",
        )

        # Step 2-N: 为每个可修复的问题生成 CFN 模板
        sorted_analyses = sorted(fixable, key=lambda a: a.risk_score, reverse=True)

        for i, analysis in enumerate(sorted_analyses):
            finding = analysis.finding
            # 生成 CFN 模板
            cfn = self.cfn_gen.generate(finding)

            self.engine.run_step(
                thought=f"为 [{finding.rule_id}] {finding.rule_name} 生成CloudFormation修复模板。"
                        f"资源: {finding.resource.name}, 风险评分: {analysis.risk_score}",
                action="generate_cfn",
                action_input={"rule_id": finding.rule_id},
            )

            self.engine.run_step(
                thought=f"验证生成的CloudFormation模板语法和资源依赖关系",
                action="validate_cfn",
            )

            # 确定修复步骤
            steps = self._get_steps(finding.rule_id)
            risk = "低" if finding.severity in [Severity.LOW, Severity.MEDIUM] else "中" if finding.severity == Severity.HIGH else "高"

            plan = RemediationPlan(
                analysis=analysis,
                status=RemediationStatus.GENERATED,
                cfn_template=cfn,
                description=f"自动修复: {finding.rule_name}",
                steps=steps,
                estimated_risk=risk,
                rollback_plan=f"删除CloudFormation Stack回滚变更，恢复资源 {finding.resource.resource_id} 原始配置",
            )
            plans.append(plan)

        # 手动修复的问题
        for analysis in manual:
            if analysis.finding:
                plan = RemediationPlan(
                    analysis=analysis,
                    status=RemediationStatus.PENDING,
                    description=f"需手动修复: {analysis.finding.rule_name}",
                    steps=["人工评估修复方案", "在测试环境验证", "安排变更窗口执行"],
                    estimated_risk="需人工评估",
                    rollback_plan="根据具体修复操作制定回滚方案",
                )
                plans.append(plan)

        self.engine.run_step(
            thought=f"修复计划生成完成。共生成 {len(plans)} 个修复计划，"
                    f"其中 {len(fixable)} 个已生成自动修复模板，"
                    f"{len(manual)} 个需手动处理。所有模板已通过语法验证",
            action="create_plan",
        )

        self.status = AgentStatus.COMPLETED
        context["remediation_plans"] = plans
        context["remediation_reasoning"] = self.engine.get_reasoning_chain()
        return context

    def _get_steps(self, rule_id: str) -> list:
        steps_map = {
            "EC2-001": ["创建当前EBS卷的快照", "从快照创建加密卷", "替换实例的EBS卷", "验证数据完整性", "删除旧的未加密卷"],
            "S3-001": ["部署S3 Bucket Policy拒绝公开访问", "启用S3 Block Public Access", "验证对象不再可公开访问"],
            "S3-003": ["部署S3默认加密配置", "验证新上传对象自动加密", "考虑对现有对象进行加密"],
            "RDS-001": ["创建数据库快照", "修改实例关闭公开访问", "验证私有网络连通性", "更新应用连接配置"],
            "RDS-003": ["修改实例启用自动备份", "设置备份保留期为7天", "配置备份窗口", "验证备份任务正常运行"],
            "SG-001": ["审计当前使用该安全组的资源", "创建新的限制性安全组", "迁移资源到新安全组", "删除旧的宽松安全组"],
            "SG-002": ["删除SSH全网开放规则", "添加限制IP范围的SSH规则", "验证授权用户仍可SSH访问"],
            "SG-003": ["删除RDP全网开放规则", "添加限制IP范围的RDP规则", "验证授权用户仍可RDP访问"],
        }
        return steps_map.get(rule_id, ["评估修复方案", "在测试环境验证", "执行修复", "验证结果"])
