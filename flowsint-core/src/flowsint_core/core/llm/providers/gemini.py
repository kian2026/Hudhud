from typing import AsyncIterator, List, Optional

from ..types import ChatMessage, MessageRole

_ROLE_MAP = {
    MessageRole.USER: "user",
    MessageRole.ASSISTANT: "model",
}


class GeminiProvider:
    def __init__(self, api_key: str, model: str = "gemini-2.0-flash"):
        from google import genai

        self._client = genai.Client(api_key=api_key)
        self._model = model

    def _get_system_instruction(self, messages: List[ChatMessage]) -> Optional[str]:
        """Extract system messages as a system_instruction."""
        parts = [m.content for m in messages if m.role == MessageRole.SYSTEM]
        return "\n\n".join(parts) if parts else None

    def _build_contents(self, messages: List[ChatMessage]):
        """Build contents list excluding system messages."""
        contents = []
        for m in messages:
            if m.role == MessageRole.SYSTEM:
                continue
            role = _ROLE_MAP[m.role]
            contents.append({"role": role, "parts": [{"text": m.content}]})
        return contents

    def _build_config(self, system_instruction: Optional[str]):
        """Build a GenerateContentConfig with system_instruction."""
        from google.genai import types

        if system_instruction:
            return types.GenerateContentConfig(
                system_instruction=system_instruction,
            )
        return None

    async def stream(self, messages: List[ChatMessage]) -> AsyncIterator[str]:
        system_instruction = self._get_system_instruction(messages)
        contents = self._build_contents(messages)
        config = self._build_config(system_instruction)

        kwargs = {"model": self._model, "contents": contents}
        if config:
            kwargs["config"] = config

        response = self._client.aio.models.generate_content_stream(**kwargs)

        async for chunk in response:
            if chunk.text:
                yield chunk.text

    async def complete(self, messages: List[ChatMessage]) -> str:
        system_instruction = self._get_system_instruction(messages)
        contents = self._build_contents(messages)
        config = self._build_config(system_instruction)

        kwargs = {"model": self._model, "contents": contents}
        if config:
            kwargs["config"] = config

        response = await self._client.aio.models.generate_content(**kwargs)

        return response.text
