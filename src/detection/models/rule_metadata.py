from dataclasses import dataclass, field
from typing import List, Optional


@dataclass(frozen=True)
class RuleMetadata:
    rule_id: str
    rule_name: str
    category: str
    severity: str
    description: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_subtechnique: Optional[str] = None
    mitre_subtechnique_id: Optional[str] = None
    mitre_url: Optional[str] = None
    references: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
