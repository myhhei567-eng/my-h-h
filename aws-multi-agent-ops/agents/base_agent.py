"""
基础 Agent 类
所有 Agent 的抽象基类
"""
from abc import ABC, abstractmethod
from core.react_engine import ReActEngine
from core.models import AgentStatus


class BaseAgent(ABC):
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
        self.engine = ReActEngine(agent_name=name)
        self.status = AgentStatus.IDLE

    @abstractmethod
    def run(self, context: dict) -> dict:
        """执行 Agent 任务，返回结果上下文"""
        pass

    def get_logs(self):
        return self.engine.logs

    def get_reasoning_chain(self):
        return self.engine.get_reasoning_chain()
