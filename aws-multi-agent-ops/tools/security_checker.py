"""
安全规则检查器
根据配置的安全规则检查资源合规性
"""
from typing import List, Dict, Any
from core.models import AWSResource, SecurityFinding, Severity, ResourceType


class SecurityChecker:
    def __init__(self, rules: Dict[str, List[Dict]]):
        self.rules = rules

    def check_resource(self, resource: AWSResource) -> List[SecurityFinding]:
        checkers = {
            ResourceType.EC2: self._check_ec2,
            ResourceType.S3: self._check_s3,
            ResourceType.RDS: self._check_rds,
            ResourceType.SECURITY_GROUP: self._check_sg,
            ResourceType.IAM: self._check_iam,
        }
        checker = checkers.get(resource.resource_type)
        if checker:
            return checker(resource)
        return []

    def check_all(self, resources: List[AWSResource]) -> List[SecurityFinding]:
        findings = []
        for r in resources:
            findings.extend(self.check_resource(r))
        return findings

    def _check_ec2(self, res: AWSResource) -> List[SecurityFinding]:
        findings = []
        cfg = res.config
        # EC2-001: EBS未加密
        for vol in cfg.get("ebs_volumes", []):
            if not vol.get("encrypted", True):
                findings.append(SecurityFinding(
                    rule_id="EC2-001", rule_name="EC2实例未加密EBS卷",
                    severity=Severity.HIGH, resource=res,
                    description=f"EBS卷 {vol['volume_id']} 未启用加密",
                    details=f"实例 {res.name} 的EBS卷 {vol['volume_id']} ({vol['size_gb']}GB) 未启用加密，存在数据泄露风险",
                ))
                break
        # EC2-002: 使用默认安全组
        for sg in cfg.get("security_groups", []):
            if "default" in sg:
                findings.append(SecurityFinding(
                    rule_id="EC2-002", rule_name="EC2实例使用默认安全组",
                    severity=Severity.MEDIUM, resource=res,
                    description=f"实例 {res.name} 使用了默认安全组 {sg}",
                    details=f"默认安全组规则不够精细，建议创建专用安全组",
                ))
                break
        # EC2-003: 无IAM角色
        if not cfg.get("iam_instance_profile"):
            findings.append(SecurityFinding(
                rule_id="EC2-003", rule_name="EC2实例无IAM角色",
                severity=Severity.MEDIUM, resource=res,
                description=f"实例 {res.name} 未关联IAM实例配置文件",
                details=f"未关联IAM角色的实例无法安全调用其他AWS服务",
            ))
        return findings

    def _check_s3(self, res: AWSResource) -> List[SecurityFinding]:
        findings = []
        cfg = res.config
        pab = cfg.get("public_access_block", {})
        # S3-001: 公开访问
        if not all([pab.get("block_public_acls"), pab.get("block_public_policy"),
                     pab.get("ignore_public_acls"), pab.get("restrict_public_buckets")]):
            if cfg.get("bucket_policy_public"):
                findings.append(SecurityFinding(
                    rule_id="S3-001", rule_name="S3存储桶公开访问",
                    severity=Severity.CRITICAL, resource=res,
                    description=f"存储桶 {res.name} 允许公开访问",
                    details=f"存储桶包含 {cfg.get('object_count', 0)} 个对象 ({cfg.get('total_size_gb', 0)}GB)，存在严重数据泄露风险",
                ))
        # S3-002: 未启用版本控制
        if not cfg.get("versioning"):
            findings.append(SecurityFinding(
                rule_id="S3-002", rule_name="S3存储桶未启用版本控制",
                severity=Severity.LOW, resource=res,
                description=f"存储桶 {res.name} 未启用版本控制",
                details=f"未启用版本控制可能导致误删数据无法恢复",
            ))
        # S3-003: 未启用加密
        if not cfg.get("encryption"):
            findings.append(SecurityFinding(
                rule_id="S3-003", rule_name="S3存储桶未启用服务端加密",
                severity=Severity.HIGH, resource=res,
                description=f"存储桶 {res.name} 未启用默认加密",
                details=f"未加密的存储桶中数据以明文存储",
            ))
        return findings

    def _check_rds(self, res: AWSResource) -> List[SecurityFinding]:
        findings = []
        cfg = res.config
        if cfg.get("publicly_accessible"):
            findings.append(SecurityFinding(
                rule_id="RDS-001", rule_name="RDS实例公开可访问",
                severity=Severity.CRITICAL, resource=res,
                description=f"RDS实例 {res.name} ({cfg['engine']}) 开启了公开访问",
                details=f"数据库端点 {cfg.get('endpoint', '')} 可从互联网直接访问，存在严重安全风险",
            ))
        if not cfg.get("multi_az"):
            findings.append(SecurityFinding(
                rule_id="RDS-002", rule_name="RDS实例未启用多可用区",
                severity=Severity.MEDIUM, resource=res,
                description=f"RDS实例 {res.name} 未启用MultiAZ",
                details=f"单可用区部署存在单点故障风险",
            ))
        if cfg.get("backup_retention_period", 1) == 0:
            findings.append(SecurityFinding(
                rule_id="RDS-003", rule_name="RDS实例未启用自动备份",
                severity=Severity.HIGH, resource=res,
                description=f"RDS实例 {res.name} 的备份保留期为0天",
                details=f"未启用自动备份，数据丢失将无法恢复",
            ))
        return findings

    def _check_sg(self, res: AWSResource) -> List[SecurityFinding]:
        findings = []
        cfg = res.config
        for rule in cfg.get("inbound_rules", []):
            src = rule.get("source", "")
            port = rule.get("port_range", "")
            if src == "0.0.0.0/0" and port == "All":
                findings.append(SecurityFinding(
                    rule_id="SG-001", rule_name="安全组开放全部入站端口",
                    severity=Severity.CRITICAL, resource=res,
                    description=f"安全组 {res.name} 允许来自0.0.0.0/0的全端口入站",
                    details=f"安全组 {res.resource_id} 对互联网完全开放，所有端口均可被访问",
                ))
            if src == "0.0.0.0/0" and port == "22":
                findings.append(SecurityFinding(
                    rule_id="SG-002", rule_name="安全组开放SSH到全网",
                    severity=Severity.HIGH, resource=res,
                    description=f"安全组 {res.name} 允许来自0.0.0.0/0的SSH访问",
                    details=f"SSH端口对互联网开放，容易遭受暴力破解攻击",
                ))
            if src == "0.0.0.0/0" and port == "3389":
                findings.append(SecurityFinding(
                    rule_id="SG-003", rule_name="安全组开放RDP到全网",
                    severity=Severity.HIGH, resource=res,
                    description=f"安全组 {res.name} 允许来自0.0.0.0/0的RDP访问",
                    details=f"RDP端口对互联网开放，容易遭受暴力破解攻击",
                ))
        return findings

    def _check_iam(self, res: AWSResource) -> List[SecurityFinding]:
        findings = []
        cfg = res.config
        if not cfg.get("mfa_enabled") and cfg.get("has_console_access", True):
            findings.append(SecurityFinding(
                rule_id="IAM-001", rule_name="IAM用户未启用MFA",
                severity=Severity.HIGH, resource=res,
                description=f"IAM用户 {res.name} 未启用多因素认证",
                details=f"用户有控制台访问权限但未启用MFA，账号容易被劫持",
            ))
        for p in cfg.get("policies", []):
            if p.get("policy_name") == "AdministratorAccess":
                findings.append(SecurityFinding(
                    rule_id="IAM-002", rule_name="IAM用户拥有管理员权限",
                    severity=Severity.CRITICAL, resource=res,
                    description=f"IAM用户 {res.name} 拥有AdministratorAccess权限",
                    details=f"最小权限原则: 用户不应直接拥有管理员权限",
                ))
        return findings
