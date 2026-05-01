"""
分析 Agent
对安全发现进行长链推理，关联多维度指标定位根因
"""
from agents.base_agent import BaseAgent
from core.models import SecurityFinding, RootCauseAnalysis, AgentStatus, Severity
from typing import List, Dict


# 根因分析知识库
ROOT_CAUSE_KB: Dict[str, Dict] = {
    "EC2-001": {
        "root_cause": "EBS卷在创建时未指定加密参数，且账号未启用EBS默认加密",
        "impact": "存储在EBS卷中的数据以明文形式存储，如果卷被快照或共享，数据可能泄露",
        "recommendation": "1. 启用账号级别的EBS默认加密 2. 创建加密快照并用加密快照恢复卷 3. 使用AWS Config规则持续监控",
    },
    "EC2-002": {
        "root_cause": "实例创建时未指定自定义安全组，自动关联了VPC默认安全组",
        "impact": "默认安全组规则可能过于宽松，且被多个资源共享，难以精细化管控",
        "recommendation": "1. 为每个应用创建专用安全组 2. 遵循最小权限原则配置入站规则 3. 定期审计安全组关联",
    },
    "EC2-003": {
        "root_cause": "实例未配置IAM实例配置文件，应用可能使用硬编码凭证访问AWS服务",
        "impact": "硬编码凭证容易泄露，且无法自动轮换，增加安全风险",
        "recommendation": "1. 创建最小权限IAM角色 2. 关联实例配置文件 3. 移除应用中的硬编码凭证",
    },
    "S3-001": {
        "root_cause": "存储桶策略允许公共访问，且未启用公共访问阻止功能",
        "impact": "存储桶中的所有对象可被互联网上任何人访问，可能导致敏感数据大规模泄露",
        "recommendation": "1. 立即启用S3公共访问阻止 2. 审计并删除公共Bucket Policy 3. 使用CloudFront分发替代直接公开",
    },
    "S3-002": {
        "root_cause": "存储桶创建时未启用版本控制功能",
        "impact": "对象被覆盖或删除后无法恢复，影响数据完整性",
        "recommendation": "1. 启用存储桶版本控制 2. 配合生命周期策略管理旧版本 3. 启用MFA Delete保护",
    },
    "S3-003": {
        "root_cause": "存储桶未配置默认服务端加密，依赖上传者手动指定加密",
        "impact": "未加密的对象以明文存储在S3中，存在数据泄露风险",
        "recommendation": "1. 启用S3默认加密(SSE-S3或SSE-KMS) 2. 添加Bucket Policy强制加密上传",
    },
    "RDS-001": {
        "root_cause": "RDS实例配置了PubliclyAccessible=true，且所在子网关联了含有公网路由的路由表",
        "impact": "数据库端点可从互联网直接访问，面临SQL注入、暴力破解等攻击风险。这是最严重的数据库安全隐患",
        "recommendation": "1. 立即设置PubliclyAccessible=false 2. 将RDS迁移到私有子网 3. 通过VPN/堡垒机访问数据库",
    },
    "RDS-002": {
        "root_cause": "RDS实例创建时未启用多可用区部署，当前为单AZ部署",
        "impact": "单可用区故障将导致数据库不可用，影响业务连续性",
        "recommendation": "1. 修改实例启用MultiAZ 2. 评估切换期间的停机影响 3. 配合只读副本提高可用性",
    },
    "RDS-003": {
        "root_cause": "RDS实例的备份保留期设置为0天，禁用了自动备份",
        "impact": "无法进行时间点恢复，数据丢失将是永久性的",
        "recommendation": "1. 设置备份保留期为7天以上 2. 定期创建手动快照 3. 测试备份恢复流程",
    },
    "SG-001": {
        "root_cause": "安全组入站规则配置了0.0.0.0/0的全端口访问，可能是临时开发配置未清理",
        "impact": "所有端口对互联网开放，实例面临各类网络攻击风险，是最严重的网络安全隐患",
        "recommendation": "1. 立即删除全开放规则 2. 按应用需求仅开放必要端口 3. 使用安全组引用替代CIDR",
    },
    "SG-002": {
        "root_cause": "SSH端口(22)对0.0.0.0/0开放，缺少IP白名单限制",
        "impact": "SSH端口暴露在互联网，面临暴力破解和未授权访问风险",
        "recommendation": "1. 限制SSH来源IP为公司网段 2. 使用SSM Session Manager替代SSH 3. 启用密钥认证禁用密码登录",
    },
    "SG-003": {
        "root_cause": "RDP端口(3389)对0.0.0.0/0开放，缺少IP白名单限制",
        "impact": "RDP端口暴露在互联网，Windows实例面临暴力破解风险",
        "recommendation": "1. 限制RDP来源IP 2. 使用VPN接入 3. 启用网络级别认证(NLA)",
    },
    "IAM-001": {
        "root_cause": "IAM用户创建后未配置多因素认证设备",
        "impact": "仅凭密码即可登录控制台，账号容易被钓鱼或暴力破解劫持",
        "recommendation": "1. 强制所有IAM用户启用MFA 2. 使用IAM策略条件键要求MFA 3. 推荐使用硬件MFA设备",
    },
    "IAM-002": {
        "root_cause": "IAM用户直接附加了AdministratorAccess托管策略，违反最小权限原则",
        "impact": "用户拥有账号中所有服务的完全控制权，误操作或账号被劫持将导致灾难性后果",
        "recommendation": "1. 移除直接的Admin权限 2. 创建细粒度的自定义策略 3. 使用IAM角色临时提权",
    },
}


class AnalyzerAgent(BaseAgent):
    def __init__(self):
        super().__init__("AnalyzerAgent", "分析Agent - 长链推理定位根因并评估影响")

    def run(self, context: dict) -> dict:
        self.status = AgentStatus.THINKING
        self.engine.reset()
        findings: List[SecurityFinding] = context.get("findings", [])
        analyses: List[RootCauseAnalysis] = []

        # Step 1: 评估总体态势
        self.engine.run_step(
            thought=f"收到 {len(findings)} 个安全发现，开始按严重程度排序并进行根因分析。"
                    f"优先处理 CRITICAL 和 HIGH 级别问题",
            action="sort_findings",
            action_input={},
        )
        self.engine.register_tool("sort_findings", lambda **kw: "按严重程度排序完成")
        self.engine.register_tool("analyze_root_cause", lambda **kw: "根因分析完成")
        self.engine.register_tool("assess_impact", lambda **kw: "影响评估完成")
        self.engine.register_tool("correlate", lambda **kw: "关联分析完成")

        # 按严重程度排序
        sorted_findings = sorted(findings, key=lambda f: f.severity.score, reverse=True)

        # Step 2-N: 逐个分析
        for i, finding in enumerate(sorted_findings):
            kb = ROOT_CAUSE_KB.get(finding.rule_id, {})
            root_cause = kb.get("root_cause", f"需要进一步调查 {finding.rule_id}")
            impact = kb.get("impact", "影响待评估")
            recommendation = kb.get("recommendation", "建议人工审查")

            # 思考推理
            self.engine.run_step(
                thought=f"分析第{i+1}个发现 [{finding.rule_id}] {finding.rule_name} "
                        f"(严重程度: {finding.severity.value}), 资源: {finding.resource.name}。"
                        f"根因: {root_cause}",
                action="analyze_root_cause",
                action_input={"rule_id": finding.rule_id},
            )

            # 影响评估
            risk_score = finding.severity.score * 10
            if finding.resource.tags.get("Environment") == "production":
                risk_score = min(100, risk_score + 20)

            self.engine.run_step(
                thought=f"影响评估: {impact}。风险评分: {risk_score}/100。"
                        f"{'⚠️ 生产环境资源，风险升级!' if finding.resource.tags.get('Environment')=='production' else ''}",
                action="assess_impact",
            )

            # 关联分析
            related = []
            for other in findings:
                if other.finding_id != finding.finding_id and other.resource.resource_id == finding.resource.resource_id:
                    related.append(other.rule_id)
            if related:
                self.engine.run_step(
                    thought=f"关联分析: 同一资源 {finding.resource.name} 还存在其他问题: {related}，问题可能相互关联",
                    action="correlate",
                )

            analysis = RootCauseAnalysis(
                finding=finding,
                root_cause=root_cause,
                impact_assessment=impact,
                risk_score=risk_score,
                related_resources=related,
                reasoning_chain=self.engine.get_reasoning_chain()[-3:],
                recommendation=recommendation,
            )
            analyses.append(analysis)

        self.status = AgentStatus.COMPLETED
        context["analyses"] = analyses
        context["analyzer_reasoning"] = self.engine.get_reasoning_chain()
        return context
