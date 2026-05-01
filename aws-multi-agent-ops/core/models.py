"""
数据模型定义
定义系统中所有核心数据结构
"""

import uuid
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


class Severity(Enum):
    """风险等级"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def score(self) -> int:
        scores = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0}
        return scores[self.value]

    @property
    def color(self) -> str:
        colors = {
            "CRITICAL": "#ff4757",
            "HIGH": "#ff6b35",
            "MEDIUM": "#ffa502",
            "LOW": "#2ed573",
            "INFO": "#70a1ff",
        }
        return colors[self.value]


class ResourceType(Enum):
    """AWS 资源类型"""
    EC2 = "ec2"
    S3 = "s3"
    RDS = "rds"
    SECURITY_GROUP = "security_group"
    IAM = "iam"


class AgentStatus(Enum):
    """Agent 运行状态"""
    IDLE = "idle"
    THINKING = "thinking"
    ACTING = "acting"
    OBSERVING = "observing"
    COMPLETED = "completed"
    ERROR = "error"


class RemediationStatus(Enum):
    """修复状态"""
    PENDING = "pending"
    GENERATED = "generated"
    APPROVED = "approved"
    APPLIED = "applied"
    FAILED = "failed"


@dataclass
class AWSResource:
    """AWS 资源"""
    resource_id: str
    resource_type: ResourceType
    name: str
    region: str
    tags: Dict[str, str] = field(default_factory=dict)
    config: Dict[str, Any] = field(default_factory=dict)
    created_at: str = ""

    def to_dict(self) -> dict:
        return {
            "resource_id": self.resource_id,
            "resource_type": self.resource_type.value,
            "name": self.name,
            "region": self.region,
            "tags": self.tags,
            "config": self.config,
            "created_at": self.created_at,
        }


@dataclass
class SecurityFinding:
    """安全发现/问题"""
    finding_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.INFO
    resource: Optional[AWSResource] = None
    description: str = ""
    details: str = ""
    detected_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "severity": self.severity.value,
            "resource": self.resource.to_dict() if self.resource else None,
            "description": self.description,
            "details": self.details,
            "detected_at": self.detected_at,
        }


@dataclass
class ReActStep:
    """ReAct 推理步骤"""
    step_number: int
    thought: str  # 思考
    action: str  # 行动
    action_input: Dict[str, Any] = field(default_factory=dict)
    observation: str = ""  # 观察结果
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "step_number": self.step_number,
            "thought": self.thought,
            "action": self.action,
            "action_input": self.action_input,
            "observation": self.observation,
            "timestamp": self.timestamp,
        }


@dataclass
class RootCauseAnalysis:
    """根因分析结果"""
    analysis_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    finding: Optional[SecurityFinding] = None
    root_cause: str = ""
    impact_assessment: str = ""
    risk_score: int = 0
    related_resources: List[str] = field(default_factory=list)
    reasoning_chain: List[ReActStep] = field(default_factory=list)
    recommendation: str = ""
    analyzed_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "analysis_id": self.analysis_id,
            "finding": self.finding.to_dict() if self.finding else None,
            "root_cause": self.root_cause,
            "impact_assessment": self.impact_assessment,
            "risk_score": self.risk_score,
            "related_resources": self.related_resources,
            "reasoning_chain": [s.to_dict() for s in self.reasoning_chain],
            "recommendation": self.recommendation,
            "analyzed_at": self.analyzed_at,
        }


@dataclass
class RemediationPlan:
    """修复计划"""
    plan_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    analysis: Optional[RootCauseAnalysis] = None
    status: RemediationStatus = RemediationStatus.PENDING
    cfn_template: str = ""
    description: str = ""
    steps: List[str] = field(default_factory=list)
    estimated_risk: str = ""
    rollback_plan: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def to_dict(self) -> dict:
        return {
            "plan_id": self.plan_id,
            "analysis": self.analysis.to_dict() if self.analysis else None,
            "status": self.status.value,
            "cfn_template": self.cfn_template,
            "description": self.description,
            "steps": self.steps,
            "estimated_risk": self.estimated_risk,
            "rollback_plan": self.rollback_plan,
            "created_at": self.created_at,
        }


@dataclass
class InspectionReport:
    """巡检报告"""
    report_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    scan_time: str = field(default_factory=lambda: datetime.now().isoformat())
    resources_scanned: int = 0
    findings: List[SecurityFinding] = field(default_factory=list)
    analyses: List[RootCauseAnalysis] = field(default_factory=list)
    remediation_plans: List[RemediationPlan] = field(default_factory=list)
    total_duration_seconds: float = 0.0
    agent_logs: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def overall_score(self) -> int:
        """安全评分 (100分制, 越高越安全)"""
        if not self.findings:
            return 100
        max_deduction = sum(f.severity.score * 3 for f in self.findings)
        score = max(0, 100 - max_deduction)
        return score

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "scan_time": self.scan_time,
            "resources_scanned": self.resources_scanned,
            "findings_count": len(self.findings),
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "overall_score": self.overall_score,
            "findings": [f.to_dict() for f in self.findings],
            "analyses": [a.to_dict() for a in self.analyses],
            "remediation_plans": [r.to_dict() for r in self.remediation_plans],
            "total_duration_seconds": self.total_duration_seconds,
            "agent_logs": self.agent_logs,
        }
