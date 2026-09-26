"""Registry of the OSINT modules, in the order the worker runs them (contract 10.4.1)."""

from qnsentry.modules.base import Module
from qnsentry.modules.placeholder import PlaceholderModule

# Each placeholder is replaced by the real module in its own issue
MODULES: list[Module] = [
    PlaceholderModule("attack_surface"),
    PlaceholderModule("metadata"),
    PlaceholderModule("phishing"),
    PlaceholderModule("breach"),
]

MODULES_BY_NAME: dict[str, Module] = {module.name: module for module in MODULES}
