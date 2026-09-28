"""Phishing Domain Detection: lookalike domains (#9), CT certificates (#10), email security (#29)."""

from qnsentry.modules.base import Finding, Module, ScanContext
from qnsentry.modules.phishing.constants import MODULE
from qnsentry.modules.phishing.lookalikes import find_lookalike_domains


class PhishingModule(Module):
    name = MODULE

    def __init__(self, nameservers: list[str] | None = None) -> None:
        # None = the resolver of the container; set e.g. ["1.1.1.1"] to use another one
        self.nameservers = nameservers

    def run(self, context: ScanContext) -> list[Finding]:
        # Certificate Transparency (#10) and email security (#29) are added here later
        return find_lookalike_domains(context.domain, nameservers=self.nameservers)
