from __future__ import annotations

from dataclasses import asdict, dataclass

from .rules import RULES


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    col: int
    rule_id: str
    message: str
    severity: str = ""
    engine: str = "odoo-sast"

    def __post_init__(self):
        if not self.severity:
            object.__setattr__(self, "severity", RULES[self.rule_id].severity)

    def to_dict(self):
        d = asdict(self)
        d["rule_name"] = RULES[self.rule_id].name if self.rule_id in RULES else self.rule_id
        return d
