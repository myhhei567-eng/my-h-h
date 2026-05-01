"""
CloudFormation 修复模板生成器
根据安全问题自动生成 CloudFormation 修复模板
"""
import json
import yaml
from typing import Dict
from core.models import SecurityFinding


class CFNGenerator:
    """根据安全发现生成 CloudFormation 修复模板"""

    REMEDIATION_MAP = {
        "EC2-001": "_fix_ec2_encryption",
        "S3-001": "_fix_s3_public_access",
        "S3-003": "_fix_s3_encryption",
        "RDS-001": "_fix_rds_public_access",
        "RDS-003": "_fix_rds_backup",
        "SG-001": "_fix_sg_wide_open",
        "SG-002": "_fix_sg_ssh",
        "SG-003": "_fix_sg_rdp",
    }

    def generate(self, finding: SecurityFinding) -> str:
        handler = self.REMEDIATION_MAP.get(finding.rule_id)
        if handler and hasattr(self, handler):
            template = getattr(self, handler)(finding)
            return yaml.dump(template, default_flow_style=False, allow_unicode=True)
        return self._generic_template(finding)

    def _base_template(self, desc: str) -> Dict:
        return {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": desc,
            "Resources": {},
        }

    def _fix_s3_public_access(self, f: SecurityFinding) -> Dict:
        t = self._base_template(f"修复 S3 存储桶 {f.resource.name} 公开访问问题")
        t["Resources"]["S3BucketPublicAccessBlock"] = {
            "Type": "AWS::S3::BucketPolicy",
            "Properties": {
                "Bucket": f.resource.resource_id,
                "PolicyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Sid": "DenyPublicAccess", "Effect": "Deny",
                        "Principal": "*", "Action": "s3:GetObject",
                        "Resource": f"arn:aws:s3:::{f.resource.resource_id}/*",
                        "Condition": {"Bool": {"aws:SecureTransport": "false"}}}]
                }
            }
        }
        return t

    def _fix_s3_encryption(self, f: SecurityFinding) -> Dict:
        t = self._base_template(f"为 S3 存储桶 {f.resource.name} 启用默认加密")
        t["Resources"]["S3BucketEncryption"] = {
            "Type": "AWS::S3::Bucket",
            "Properties": {
                "BucketName": f.resource.resource_id,
                "BucketEncryption": {
                    "ServerSideEncryptionConfiguration": [{
                        "ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
                    }]
                }
            }
        }
        return t

    def _fix_rds_public_access(self, f: SecurityFinding) -> Dict:
        t = self._base_template(f"关闭 RDS 实例 {f.resource.name} 的公开访问")
        t["Resources"]["RDSInstance"] = {
            "Type": "AWS::RDS::DBInstance",
            "Properties": {
                "DBInstanceIdentifier": f.resource.resource_id,
                "PubliclyAccessible": False,
            }
        }
        return t

    def _fix_rds_backup(self, f: SecurityFinding) -> Dict:
        t = self._base_template(f"为 RDS 实例 {f.resource.name} 启用自动备份")
        t["Resources"]["RDSInstance"] = {
            "Type": "AWS::RDS::DBInstance",
            "Properties": {
                "DBInstanceIdentifier": f.resource.resource_id,
                "BackupRetentionPeriod": 7,
                "PreferredBackupWindow": "03:00-04:00",
            }
        }
        return t

    def _fix_ec2_encryption(self, f: SecurityFinding) -> Dict:
        t = self._base_template(f"为 EC2 实例 {f.resource.name} 的 EBS 卷启用加密")
        t["Resources"]["EBSEncryptionDefault"] = {
            "Type": "AWS::EC2::Volume",
            "Properties": {
                "AvailabilityZone": f"{f.resource.region}a",
                "Encrypted": True,
                "Size": 50,
                "Tags": [{"Key": "Name", "Value": f"{f.resource.name}-encrypted"}]
            }
        }
        return t

    def _fix_sg_wide_open(self, f: SecurityFinding) -> Dict:
        t = self._base_template(f"修复安全组 {f.resource.name} 全端口开放问题")
        t["Resources"]["SecurityGroupFix"] = {
            "Type": "AWS::EC2::SecurityGroup",
            "Properties": {
                "GroupDescription": f"Fixed: {f.resource.name}",
                "VpcId": f.resource.config.get("vpc_id", ""),
                "SecurityGroupIngress": [
                    {"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "10.0.0.0/16"},
                    {"IpProtocol": "tcp", "FromPort": 80, "ToPort": 80, "CidrIp": "10.0.0.0/16"},
                ]
            }
        }
        return t

    def _fix_sg_ssh(self, f: SecurityFinding) -> Dict:
        t = self._base_template(f"限制安全组 {f.resource.name} 的 SSH 访问来源")
        t["Resources"]["SSHIngressFix"] = {
            "Type": "AWS::EC2::SecurityGroupIngress",
            "Properties": {
                "GroupId": f.resource.resource_id,
                "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                "CidrIp": "10.0.0.0/16",
                "Description": "仅允许内网SSH访问"
            }
        }
        return t

    def _fix_sg_rdp(self, f: SecurityFinding) -> Dict:
        t = self._base_template(f"限制安全组 {f.resource.name} 的 RDP 访问来源")
        t["Resources"]["RDPIngressFix"] = {
            "Type": "AWS::EC2::SecurityGroupIngress",
            "Properties": {
                "GroupId": f.resource.resource_id,
                "IpProtocol": "tcp", "FromPort": 3389, "ToPort": 3389,
                "CidrIp": "10.0.0.0/16",
                "Description": "仅允许内网RDP访问"
            }
        }
        return t

    def _generic_template(self, f: SecurityFinding) -> str:
        return f"# 规则 {f.rule_id}: {f.rule_name}\n# 需要手动修复\n# 资源: {f.resource.resource_id}\n# 建议: {f.description}\n"
