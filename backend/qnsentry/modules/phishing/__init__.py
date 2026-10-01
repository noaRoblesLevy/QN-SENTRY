"""Phishing Domain Detection: lookalike domains (#9), CT certificates (#10), email security (#29)."""

import logging

from qnsentry.modules.base import Finding, Module, ScanContext
from qnsentry.modules.phishing.constants import MODULE
from qnsentry.modules.phishing.email_security import check_email_security
from qnsentry.modules.phishing.lookalikes import find_lookalike_domains

log = logging.getLogger(__name__)


class PhishingModule(Module):
    name = MODULE

    def __init__(self, nameservers: list[str] | None = None) -> None:
        # None = the resolver of the container; set e.g. ["1.1.1.1"] to use another one
        self.nameservers = nameservers

    def run(self, context: ScanContext) -> list[Finding]:
        # Each check runs on its own: if one fails, the findings of the others are kept
        # (data contract 10.3.1). Certificate Transparency (#10) is added here later.
        checks = {
            "lookalike domains": find_lookalike_domains,
            "email security": check_email_security,
        }
        findings: list[Finding] = []
        errors: list[str] = []
        for label, check in checks.items():
            try:
                findings += check(context.domain, nameservers=self.nameservers)
            except Exception as error:
                log.warning("Phishing check '%s' failed for %s: %s", label, context.domain, error)
                errors.append(f"{label}: {error}")

        if len(errors) == len(checks):
            # Nothing useful to return: let the worker mark the module as failed
            raise RuntimeError("; ".join(errors))
        return findings
