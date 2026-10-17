from typing import List

from src.detection.rules.access_denied_rule import RepeatedAccessDeniedRule
from src.detection.rules.application.repeated_application_error_rule import (
    RepeatedApplicationErrorRule,
)
from src.detection.rules.authentication.multiple_account_target_rule import (
    MultipleAccountTargetRule,
)
from src.detection.rules.authentication.multiple_source_login_rule import (
    MultipleSourceLoginRule,
)
from src.detection.rules.base_rule import BaseDetectionRule
from src.detection.rules.excessive_request_rule import ExcessiveRequestRule
from src.detection.rules.failed_login_rule import MultipleFailedLoginRule
from src.detection.rules.firewall.repeated_denied_rule import (
    RepeatedFirewallDeniedRule,
)
from src.detection.rules.password_spraying_rule import PasswordSprayingRule
from src.detection.rules.restricted_resource_rule import RestrictedResourceRule
from src.detection.rules.successful_login_after_failures_rule import (
    SuccessfulLoginAfterFailuresRule,
)
from src.detection.rules.system.repeated_service_failure_rule import (
    RepeatedServiceFailureRule,
)
from src.detection.rules.unusual_login_time_rule import UnusualLoginTimeRule
from src.detection.rules.web.repeated_404_rule import Repeated404Rule
from src.detection.rules.web.repeated_5xx_rule import Repeated5xxRule
from src.detection.rules.web.sensitive_path_rule import SensitivePathRule


def get_rule_library() -> List[BaseDetectionRule]:
    return [
        MultipleFailedLoginRule(),
        RepeatedAccessDeniedRule(),
        UnusualLoginTimeRule(),
        SuccessfulLoginAfterFailuresRule(),
        PasswordSprayingRule(),
        MultipleAccountTargetRule(),
        MultipleSourceLoginRule(),
        RestrictedResourceRule(),
        ExcessiveRequestRule(),
        Repeated404Rule(),
        Repeated5xxRule(),
        SensitivePathRule(),
        RepeatedFirewallDeniedRule(),
        RepeatedApplicationErrorRule(),
        RepeatedServiceFailureRule(),
    ]
