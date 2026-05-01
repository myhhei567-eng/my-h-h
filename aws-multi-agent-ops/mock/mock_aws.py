"""
Mock AWS 数据生成器
模拟 AWS 环境中的各种资源，包含正常和异常配置
用于在没有真实 AWS 凭证的情况下演示系统功能
"""

from core.models import AWSResource, ResourceType


def generate_mock_resources():
    """生成模拟 AWS 资源数据，包含多种安全隐患"""

    resources = []

    # ===== EC2 实例 =====
    resources.append(AWSResource(
        resource_id="i-0a1b2c3d4e5f60001",
        resource_type=ResourceType.EC2,
        name="web-server-prod-01",
        region="ap-northeast-1",
        tags={"Environment": "production", "Team": "backend"},
        config={
            "instance_type": "t3.medium",
            "state": "running",
            "public_ip": "54.199.100.10",
            "private_ip": "10.0.1.100",
            "security_groups": ["sg-default-001"],  # 使用默认安全组 -> 触发 EC2-002
            "iam_instance_profile": None,  # 无IAM角色 -> 触发 EC2-003
            "ebs_volumes": [
                {"volume_id": "vol-001", "encrypted": False, "size_gb": 50}  # 未加密 -> 触发 EC2-001
            ],
            "vpc_id": "vpc-0abc001",
            "subnet_id": "subnet-pub-001",
        },
        created_at="2025-11-15T08:30:00Z",
    ))

    resources.append(AWSResource(
        resource_id="i-0a1b2c3d4e5f60002",
        resource_type=ResourceType.EC2,
        name="api-server-prod-01",
        region="ap-northeast-1",
        tags={"Environment": "production", "Team": "backend"},
        config={
            "instance_type": "t3.large",
            "state": "running",
            "public_ip": None,
            "private_ip": "10.0.2.50",
            "security_groups": ["sg-api-001"],
            "iam_instance_profile": "arn:aws:iam::123456789:instance-profile/api-role",
            "ebs_volumes": [
                {"volume_id": "vol-002", "encrypted": True, "size_gb": 100}
            ],
            "vpc_id": "vpc-0abc001",
            "subnet_id": "subnet-priv-001",
        },
        created_at="2025-12-01T10:00:00Z",
    ))

    resources.append(AWSResource(
        resource_id="i-0a1b2c3d4e5f60003",
        resource_type=ResourceType.EC2,
        name="dev-test-server",
        region="ap-northeast-1",
        tags={"Environment": "dev"},
        config={
            "instance_type": "t3.micro",
            "state": "running",
            "public_ip": "54.199.100.20",
            "private_ip": "10.0.3.10",
            "security_groups": ["sg-wide-open-001"],
            "iam_instance_profile": None,  # 无IAM角色
            "ebs_volumes": [
                {"volume_id": "vol-003", "encrypted": False, "size_gb": 20}  # 未加密
            ],
            "vpc_id": "vpc-0abc001",
            "subnet_id": "subnet-pub-002",
        },
        created_at="2026-01-20T14:00:00Z",
    ))

    # ===== S3 存储桶 =====
    resources.append(AWSResource(
        resource_id="company-public-assets-bucket",
        resource_type=ResourceType.S3,
        name="company-public-assets-bucket",
        region="ap-northeast-1",
        tags={"Environment": "production"},
        config={
            "public_access_block": {
                "block_public_acls": False,  # 公开访问 -> 触发 S3-001
                "block_public_policy": False,
                "ignore_public_acls": False,
                "restrict_public_buckets": False,
            },
            "versioning": False,  # 未启用版本控制 -> 触发 S3-002
            "encryption": None,  # 未启用加密 -> 触发 S3-003
            "bucket_policy_public": True,
            "object_count": 15420,
            "total_size_gb": 128.5,
        },
        created_at="2025-06-10T05:00:00Z",
    ))

    resources.append(AWSResource(
        resource_id="company-logs-bucket",
        resource_type=ResourceType.S3,
        name="company-logs-bucket",
        region="ap-northeast-1",
        tags={"Environment": "production", "Team": "ops"},
        config={
            "public_access_block": {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
            "versioning": True,
            "encryption": "AES256",
            "bucket_policy_public": False,
            "object_count": 892340,
            "total_size_gb": 2048.0,
        },
        created_at="2025-03-01T00:00:00Z",
    ))

    resources.append(AWSResource(
        resource_id="company-backup-data",
        resource_type=ResourceType.S3,
        name="company-backup-data",
        region="ap-northeast-1",
        tags={"Environment": "production"},
        config={
            "public_access_block": {
                "block_public_acls": True,
                "block_public_policy": True,
                "ignore_public_acls": True,
                "restrict_public_buckets": True,
            },
            "versioning": False,  # 未启用版本控制
            "encryption": "aws:kms",
            "bucket_policy_public": False,
            "object_count": 50200,
            "total_size_gb": 512.0,
        },
        created_at="2025-04-15T12:00:00Z",
    ))

    # ===== RDS 实例 =====
    resources.append(AWSResource(
        resource_id="db-prod-mysql-001",
        resource_type=ResourceType.RDS,
        name="prod-mysql-main",
        region="ap-northeast-1",
        tags={"Environment": "production", "Team": "backend"},
        config={
            "engine": "mysql",
            "engine_version": "8.0.35",
            "instance_class": "db.r6g.large",
            "publicly_accessible": True,  # 公开可访问 -> 触发 RDS-001
            "multi_az": False,  # 未启用多可用区 -> 触发 RDS-002
            "storage_encrypted": True,
            "backup_retention_period": 0,  # 未启用自动备份 -> 触发 RDS-003
            "vpc_id": "vpc-0abc001",
            "endpoint": "prod-mysql-main.xxxx.ap-northeast-1.rds.amazonaws.com",
            "port": 3306,
            "allocated_storage_gb": 200,
        },
        created_at="2025-08-20T09:00:00Z",
    ))

    resources.append(AWSResource(
        resource_id="db-prod-postgres-001",
        resource_type=ResourceType.RDS,
        name="prod-postgres-analytics",
        region="ap-northeast-1",
        tags={"Environment": "production", "Team": "data"},
        config={
            "engine": "postgres",
            "engine_version": "15.4",
            "instance_class": "db.r6g.xlarge",
            "publicly_accessible": False,
            "multi_az": True,
            "storage_encrypted": True,
            "backup_retention_period": 7,
            "vpc_id": "vpc-0abc001",
            "endpoint": "prod-postgres-analytics.xxxx.ap-northeast-1.rds.amazonaws.com",
            "port": 5432,
            "allocated_storage_gb": 500,
        },
        created_at="2025-09-10T11:00:00Z",
    ))

    # ===== 安全组 =====
    resources.append(AWSResource(
        resource_id="sg-default-001",
        resource_type=ResourceType.SECURITY_GROUP,
        name="default",
        region="ap-northeast-1",
        tags={},
        config={
            "vpc_id": "vpc-0abc001",
            "description": "default VPC security group",
            "inbound_rules": [
                {"protocol": "-1", "port_range": "All", "source": "sg-default-001"}
            ],
            "outbound_rules": [
                {"protocol": "-1", "port_range": "All", "destination": "0.0.0.0/0"}
            ],
            "is_default": True,
        },
    ))

    resources.append(AWSResource(
        resource_id="sg-wide-open-001",
        resource_type=ResourceType.SECURITY_GROUP,
        name="wide-open-dev-sg",
        region="ap-northeast-1",
        tags={"Environment": "dev"},
        config={
            "vpc_id": "vpc-0abc001",
            "description": "Dev security group - TEMP wide open",
            "inbound_rules": [
                {"protocol": "-1", "port_range": "All", "source": "0.0.0.0/0"},  # 全端口开放 -> 触发 SG-001
                {"protocol": "tcp", "port_range": "22", "source": "0.0.0.0/0"},  # SSH开放 -> 触发 SG-002
                {"protocol": "tcp", "port_range": "3389", "source": "0.0.0.0/0"},  # RDP开放 -> 触发 SG-003
            ],
            "outbound_rules": [
                {"protocol": "-1", "port_range": "All", "destination": "0.0.0.0/0"}
            ],
            "is_default": False,
        },
    ))

    resources.append(AWSResource(
        resource_id="sg-api-001",
        resource_type=ResourceType.SECURITY_GROUP,
        name="api-server-sg",
        region="ap-northeast-1",
        tags={"Environment": "production"},
        config={
            "vpc_id": "vpc-0abc001",
            "description": "API server security group",
            "inbound_rules": [
                {"protocol": "tcp", "port_range": "443", "source": "10.0.0.0/16"},
                {"protocol": "tcp", "port_range": "8080", "source": "10.0.0.0/16"},
            ],
            "outbound_rules": [
                {"protocol": "-1", "port_range": "All", "destination": "0.0.0.0/0"}
            ],
            "is_default": False,
        },
    ))

    # ===== IAM 用户 =====
    resources.append(AWSResource(
        resource_id="AIDA1234567890ADMIN",
        resource_type=ResourceType.IAM,
        name="admin-user",
        region="global",
        tags={"Department": "IT"},
        config={
            "user_type": "IAM User",
            "mfa_enabled": False,  # 未启用MFA -> 触发 IAM-001
            "has_console_access": True,
            "access_keys": [
                {"key_id": "AKIA...XYZ1", "status": "Active", "last_used": "2026-04-29"}
            ],
            "policies": [
                {"policy_name": "AdministratorAccess", "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"}  # 管理员权限 -> 触发 IAM-002
            ],
            "groups": ["Administrators"],
            "last_login": "2026-04-29T15:30:00Z",
        },
        created_at="2025-01-10T00:00:00Z",
    ))

    resources.append(AWSResource(
        resource_id="AIDA1234567890DEV01",
        resource_type=ResourceType.IAM,
        name="developer-01",
        region="global",
        tags={"Department": "Engineering"},
        config={
            "user_type": "IAM User",
            "mfa_enabled": True,
            "has_console_access": True,
            "access_keys": [
                {"key_id": "AKIA...ABC1", "status": "Active", "last_used": "2026-04-28"}
            ],
            "policies": [
                {"policy_name": "PowerUserAccess", "policy_arn": "arn:aws:iam::aws:policy/PowerUserAccess"}
            ],
            "groups": ["Developers"],
            "last_login": "2026-04-28T10:00:00Z",
        },
        created_at="2025-05-20T00:00:00Z",
    ))

    resources.append(AWSResource(
        resource_id="AIDA1234567890CICD",
        resource_type=ResourceType.IAM,
        name="cicd-service-user",
        region="global",
        tags={"Department": "DevOps"},
        config={
            "user_type": "IAM User",
            "mfa_enabled": False,  # CI/CD用户未启用MFA -> 触发 IAM-001
            "has_console_access": False,
            "access_keys": [
                {"key_id": "AKIA...DEF1", "status": "Active", "last_used": "2026-04-30"}
            ],
            "policies": [
                {"policy_name": "AmazonEC2FullAccess", "policy_arn": "arn:aws:iam::aws:policy/AmazonEC2FullAccess"},
                {"policy_name": "AmazonS3FullAccess", "policy_arn": "arn:aws:iam::aws:policy/AmazonS3FullAccess"},
            ],
            "groups": ["CICD"],
            "last_login": None,
        },
        created_at="2025-07-01T00:00:00Z",
    ))

    return resources
