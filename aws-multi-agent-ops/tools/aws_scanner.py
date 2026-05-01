"""
AWS 资源扫描器
扫描 AWS 资源并返回资源列表
"""
from typing import List
from core.models import AWSResource, ResourceType


class AWSScanner:
    def __init__(self, mode="mock", region="ap-northeast-1"):
        self.mode = mode
        self.region = region
        self._resources: List[AWSResource] = []

    def load_resources(self, resources: List[AWSResource]):
        self._resources = resources

    def scan_all(self) -> List[AWSResource]:
        if self.mode == "mock":
            return self._resources
        # live 模式可扩展 boto3 调用
        return []

    def scan_by_type(self, resource_type: str) -> List[AWSResource]:
        rt = ResourceType(resource_type)
        return [r for r in self._resources if r.resource_type == rt]

    def get_resource(self, resource_id: str):
        for r in self._resources:
            if r.resource_id == resource_id:
                return r
        return None
