"""CLI registration for pre-0.6 released-store migration."""

from ...legacy.pre_0_6_0.cli import (
    ConfigMigrateApplyCLI,
    ConfigMigrateModalCLI,
    ConfigMigratePlanCLI,
    ConfigMigrateResumeCLI,
    ConfigMigrateRollbackCLI,
    ConfigMigrateStatusCLI,
    ConfigMigrateVerifyCLI,
)

__all__ = [
    'ConfigMigrateApplyCLI',
    'ConfigMigrateModalCLI',
    'ConfigMigratePlanCLI',
    'ConfigMigrateResumeCLI',
    'ConfigMigrateRollbackCLI',
    'ConfigMigrateStatusCLI',
    'ConfigMigrateVerifyCLI',
]
