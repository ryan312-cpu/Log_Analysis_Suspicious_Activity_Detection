from abc import ABC, abstractmethod
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.policy_manager import PolicyManager
from src.storage.models import EventModel


class BaseDetectionRule(ABC):

    metadata: RuleMetadata

    @abstractmethod
    def evaluate(
        self,
        events: List[EventModel],
    ) -> List[Alert]:
        pass

    @property
    def rule_id(self) -> str:
        return self.metadata.rule_id

    @property
    def rule_name(self) -> str:
        rule_pol = PolicyManager.get_instance().get_rule_policy(self.rule_id)
        if rule_pol and rule_pol.rule_name:
            return rule_pol.rule_name
        return self.metadata.rule_name

    @property
    def severity(self) -> str:
        return PolicyManager.get_instance().get_severity(self.rule_id, default=self.metadata.severity)

    @property
    def is_enabled(self) -> bool:
        return PolicyManager.get_instance().is_rule_enabled(self.rule_id)

    def get_configured_threshold(self, default: int = 5) -> int:
        return PolicyManager.get_instance().get_threshold(self.rule_id, default=default)
