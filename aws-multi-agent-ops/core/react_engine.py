"""
ReAct 推理引擎
实现 Thought -> Action -> Observation 循环推理框架
"""
import time
from typing import Callable, Dict, Any, List
from core.models import ReActStep, AgentStatus


class ReActEngine:
    def __init__(self, agent_name: str, max_steps: int = 10):
        self.agent_name = agent_name
        self.max_steps = max_steps
        self.tools: Dict[str, Callable] = {}
        self.steps: List[ReActStep] = []
        self.status = AgentStatus.IDLE
        self.logs: List[Dict[str, Any]] = []

    def register_tool(self, name: str, func: Callable, description: str = ""):
        self.tools[name] = func
        self._log("TOOL_REGISTERED", f"注册工具: {name} - {description}")

    def _log(self, event: str, message: str):
        self.logs.append({
            "agent": self.agent_name,
            "event": event,
            "message": message,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        })

    def run_step(self, thought: str, action: str, action_input: Dict[str, Any] = None) -> ReActStep:
        step_num = len(self.steps) + 1
        self.status = AgentStatus.THINKING
        self._log("THOUGHT", f"[Step {step_num}] {thought}")
        step = ReActStep(step_number=step_num, thought=thought, action="")

        self.status = AgentStatus.ACTING
        step.action = action
        step.action_input = action_input or {}
        self._log("ACTION", f"[Step {step_num}] 执行: {action}")

        if action in self.tools:
            try:
                result = self.tools[action](**(action_input or {}))
                step.observation = str(result) if result is not None else "执行成功"
            except Exception as e:
                step.observation = f"工具执行错误: {str(e)}"
        else:
            step.observation = f"未知工具: {action}"

        self.status = AgentStatus.OBSERVING
        self._log("OBSERVATION", f"[Step {step_num}] {step.observation[:200]}")
        self.steps.append(step)
        time.sleep(0.05)
        return step

    def get_reasoning_chain(self) -> List[ReActStep]:
        return self.steps.copy()

    def reset(self):
        self.steps = []
        self.status = AgentStatus.IDLE
        self.logs = []
