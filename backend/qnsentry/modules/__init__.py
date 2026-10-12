"""Registry of the OSINT modules, in the order the worker runs them (contract 10.4.1)."""

from qnsentry.modules.attack_surface import AttackSurfaceModule
from qnsentry.modules.base import Module
from qnsentry.modules.breach import BreachModule
from qnsentry.modules.metadata import MetadataModule
from qnsentry.modules.phishing import PhishingModule

MODULES: list[Module] = [
    AttackSurfaceModule(),
    MetadataModule(),
    PhishingModule(),
    BreachModule(),
]

MODULES_BY_NAME: dict[str, Module] = {module.name: module for module in MODULES}
