"""Customizable Organization Security Policy Engine.

Loads, validates, and manages organizational detection rules, thresholds,
severity mappings, and enablement flags from JSON or database.
"""
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

POLICY_FILE_PATH = Path("config/security_policy.json")


class RulePolicyModel(BaseModel):
    rule_name: Optional[str] = None
    enabled: bool = True
    severity: str = "HIGH"
    threshold: Optional[int] = None
    allowed_start_hour: Optional[int] = None
    allowed_end_hour: Optional[int] = None
    failed_threshold: Optional[int] = None
    window_seconds: Optional[int] = None
    unique_users_threshold: Optional[int] = None
    account_threshold: Optional[int] = None
    distinct_ips_threshold: Optional[int] = None
    restricted_paths: Optional[list[str]] = None
    description: Optional[str] = None


class SecurityPolicyConfig(BaseModel):
    organization_name: str = "Default Security Organization"
    policy_version: str = "1.0.0"
    last_updated: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    rules: Dict[str, RulePolicyModel] = Field(default_factory=dict)


class PolicyManager:
    """Singleton service to query and update organizational security policies."""

    _instance: Optional["PolicyManager"] = None

    def __init__(self, policy_path: Path = POLICY_FILE_PATH):
        self.policy_path = policy_path
        self._policy: SecurityPolicyConfig = self._load_policy()

    @classmethod
    def get_instance(cls) -> "PolicyManager":
        if cls._instance is None:
            cls._instance = cls()
        return cls._instance

    def _load_policy(self) -> SecurityPolicyConfig:
        if not self.policy_path.exists():
            logger.warning("Policy file %s not found. Creating defaults.", self.policy_path)
            default_config = SecurityPolicyConfig()
            self._save_policy(default_config)
            return default_config

        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return SecurityPolicyConfig(**data)
        except Exception as e:
            logger.error("Failed to parse policy file %s: %s. Using in-memory defaults.", self.policy_path, e)
            return SecurityPolicyConfig()

    def _save_policy(self, config: SecurityPolicyConfig) -> None:
        self.policy_path.parent.mkdir(parents=True, exist_ok=True)
        config.last_updated = datetime.now(timezone.utc).isoformat()
        with open(self.policy_path, "w", encoding="utf-8") as f:
            f.write(config.model_dump_json(indent=2))

    def get_policy(self) -> SecurityPolicyConfig:
        return self._policy

    def get_rule_policy(self, rule_id: str) -> Optional[RulePolicyModel]:
        return self._policy.rules.get(rule_id)

    def is_rule_enabled(self, rule_id: str) -> bool:
        rule_pol = self.get_rule_policy(rule_id)
        return rule_pol.enabled if rule_pol else True

    def get_threshold(self, rule_id: str, default: int = 5) -> int:
        rule_pol = self.get_rule_policy(rule_id)
        if rule_pol and rule_pol.threshold is not None:
            return rule_pol.threshold
        return default

    def get_severity(self, rule_id: str, default: str = "HIGH") -> str:
        rule_pol = self.get_rule_policy(rule_id)
        if rule_pol and rule_pol.severity:
            return rule_pol.severity
        return default

    def update_rule_policy(self, rule_id: str, updates: Dict[str, Any]) -> RulePolicyModel:
        if rule_id not in self._policy.rules:
            self._policy.rules[rule_id] = RulePolicyModel(**updates)
        else:
            current = self._policy.rules[rule_id].model_dump()
            current.update(updates)
            self._policy.rules[rule_id] = RulePolicyModel(**current)

        self._save_policy(self._policy)
        return self._policy.rules[rule_id]

    def update_organization(self, organization_name: str) -> SecurityPolicyConfig:
        self._policy.organization_name = organization_name
        self._save_policy(self._policy)
        return self._policy

    def reload(self) -> SecurityPolicyConfig:
        self._policy = self._load_policy()
        return self._policy
