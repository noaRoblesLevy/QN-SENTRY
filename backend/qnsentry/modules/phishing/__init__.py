"""Phishing Domain Detection: lookalike domains (#9), CT certificates (#10), email security (#29)."""

import logging
from collections.abc import Callable

from qnsentry.modules.base import Finding, Module, ScanContext
from qnsentry.modules.phishing.certificates import configured_api_key, find_lookalike_certificates
from qnsentry.modules.phishing.constants import MODULE
from qnsentry.modules.phishing.email_security import check_email_security
from qnsentry.modules.phishing.lookalikes import check_resolver, find_lookalike_domains

log = logging.getLogger(__name__)


class PhishingModule(Module):
    name = MODULE

    def __init__(self, nameservers: list[str] | None = None) -> None:
        # None = DNS_SERVERS from the settings (#80); set e.g. ["1.1.1.1"] to use other servers
        self.nameservers = nameservers

    def run(self, context: ScanContext) -> list[Finding]:
        # Each check runs on its own: if one fails, the findings of the others are kept
        # (data contract 10.3.1). Only when every check fails does the module fail.
        domain = context.domain
        errors: list[str] = []
        nameservers = self.nameservers or reachable_nameservers(configured_nameservers())

        lookalikes = self._check(
            "lookalike domains", lambda: find_lookalike_domains(domain, nameservers=nameservers), domain, errors
        )
        # The certificate check looks up the lookalikes found above. Without them it cannot
        # run at all, which counts as a failure (otherwise a module with nothing checked
        # could still end as "completed").
        if errors:
            errors.append("lookalike certificates: skipped because the lookalike check failed")
            certificates: list[Finding] = []
        else:
            certificates = self._check(
                "lookalike certificates",
                lambda: find_lookalike_certificates(lookalikes, api_key=configured_api_key(), warn=context.warn),
                domain,
                errors,
            )
        email = self._check(
            "email security",
            lambda: check_email_security(domain, nameservers=nameservers, warn=context.warn),
            domain,
            errors,
        )

        if len(errors) == 3:
            # Nothing useful to return: let the worker mark the module as failed
            raise RuntimeError("; ".join(errors))
        # A check that failed while others worked: the module completes, with a warning per
        # check, so a skipped check never looks like a clean result (data contract 10.3.1)
        for error in errors:
            label, _, reason = error.partition(": ")
            context.warn(f"The {label} check did not run: {reason}")
        return lookalikes + certificates + email

    @staticmethod
    def _check(label: str, check: Callable[[], list[Finding]], domain: str, errors: list[str]) -> list[Finding]:
        try:
            return check()
        except Exception as error:
            log.warning("Phishing check '%s' failed for %s: %s", label, domain, error)
            errors.append(f"{label}: {error}")
            return []


def configured_nameservers() -> list[str] | None:
    from qnsentry.config import settings

    return settings.nameservers


def reachable_nameservers(nameservers: list[str] | None) -> list[str] | None:
    """The configured DNS servers, or the container's DNS when they cannot be used: some
    networks block DNS to servers outside the network. The results stay reliable either way,
    because the lookalike check tests the resolver it gets (#54); only slower on some networks."""
    if not nameservers:
        return None
    try:
        check_resolver(nameservers)
    except RuntimeError as error:
        log.warning("DNS_SERVERS cannot be used, falling back to the container's DNS: %s", error)
        return None
    return nameservers
