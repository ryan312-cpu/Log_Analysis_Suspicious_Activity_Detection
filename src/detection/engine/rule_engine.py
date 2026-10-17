from typing import List

from src.detection.models.alert import Alert
from src.detection.models.rule_metadata import RuleMetadata
from src.detection.rules.base_rule import BaseDetectionRule


class DetectionEngine:

    def __init__(
        self,
        rules: List[BaseDetectionRule],
    ):
        rule_ids = [rule.rule_id for rule in rules]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Rule IDs must be unique")
        self.rules = rules

    @property
    def rule_metadata(self) -> List[RuleMetadata]:
        return [rule.metadata for rule in self.rules]

    def run(
        self,
        events,
    ) -> List[Alert]:

        all_alerts = []

        for rule in self.rules:

            alerts = rule.evaluate(events)

            all_alerts.extend(alerts)

        return all_alerts
