"""
Validation and adversary emulation package for controlled security testing.
"""
from src.validation.scenario_generator import (
    scenario_brute_force,
    scenario_password_spraying,
    scenario_login_after_failures,
    scenario_web_enumeration,
    scenario_excessive_requests,
    scenario_firewall_denial_burst,
    scenario_application_errors,
    scenario_service_failures,
)
from src.validation.controlled_runner import run_controlled_validation, save_results

__all__ = [
    "scenario_brute_force",
    "scenario_password_spraying",
    "scenario_login_after_failures",
    "scenario_web_enumeration",
    "scenario_excessive_requests",
    "scenario_firewall_denial_burst",
    "scenario_application_errors",
    "scenario_service_failures",
    "run_controlled_validation",
    "save_results",
]
