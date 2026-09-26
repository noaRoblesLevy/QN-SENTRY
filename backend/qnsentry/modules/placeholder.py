import time

from qnsentry.db.models import Severity
from qnsentry.modules.base import Finding, Module, ScanContext


class PlaceholderModule(Module):
    """Stand-in for a module that has not been built yet (walking skeleton, #1).

    It pretends to work for a few seconds and returns one informational finding,
    so the whole chain can be tested before the real modules exist.
    """

    def __init__(self, name: str, duration: float = 3.0) -> None:
        self.name = name
        self.duration = duration

    def run(self, context: ScanContext) -> list[Finding]:
        time.sleep(self.duration)
        return [
            Finding(
                module=self.name,
                type="placeholder",
                title=f"Placeholder finding for {context.domain}",
                description="This module has not been implemented yet.",
                severity=Severity.INFO,
                asset=context.domain,
            )
        ]
