from __future__ import annotations

from typing import Any

from langchain_core.runnables import Runnable

from ..errors import SecurityError


class SecureRunnable:
    def __init__(self, runnable: Runnable, detector: Any):
        self._runnable = runnable
        self._detector = detector

    def invoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        result = self._detector.scan(str(input))
        if result.blocked:
            raise SecurityError(result.reason or "Request blocked by security policy.")
        return self._runnable.invoke(input, config=config, **kwargs)

    async def ainvoke(self, input: Any, config: Any = None, **kwargs: Any) -> Any:
        result = self._detector.scan(str(input))
        if result.blocked:
            raise SecurityError(result.reason or "Request blocked by security policy.")
        return await self._runnable.ainvoke(input, config=config, **kwargs)