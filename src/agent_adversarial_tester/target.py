"""Agent target interface — connect any agent for red teaming."""

from __future__ import annotations

from abc import ABC, abstractmethod


class AgentTarget(ABC):
    """Base class for connecting your agent to the red team harness.

    Implement `invoke()` at minimum. Override other methods for
    deeper analysis (tool call tracking, system prompt extraction checks).
    """

    def setup(self) -> None:
        """Initialize your agent. Called once before all attacks."""

    @abstractmethod
    async def invoke(self, message: str) -> str:
        """Send a message to your agent and return its response.

        This is the only method you MUST implement.
        """
        ...

    async def invoke_conversation(self, messages: list[dict]) -> str:
        """Multi-turn conversation for escalation attacks.

        Override for agents that support conversation history.
        Default: sends only the last message.
        """
        last = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                last = msg["content"]
                break
        return await self.invoke(last)

    def get_tool_calls(self) -> list[dict]:
        """Return tool calls from the last invocation.

        Format: [{"name": "tool_name", "arguments": {...}}]
        Return empty list if not available or not tracked.
        """
        return []

    def get_system_prompt(self) -> str:
        """Return the agent's system prompt for extraction detection.

        Used to check if the agent leaked its own instructions.
        Return empty string to skip this detection.
        """
        return ""

    def teardown(self) -> None:
        """Cleanup. Called once after all attacks."""
