from abc import ABC, abstractmethod
from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
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
        return self.metadata.rule_name

    @property
    def severity(self) -> str:
        return self.metadata.severity
