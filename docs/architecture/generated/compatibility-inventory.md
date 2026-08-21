<!-- GENERATED FILE - DO NOT EDIT -->
<!-- generation schema: 2 -->
# Compatibility and transitional architecture inventory

This inventory is observational. The legacy-import allowlist is enforced;
the aggregate-config and scope-reconstruction lists are intended to shrink.

## Canonical imports of `aivm.legacy.pre_0_6_0` (20)

| Importer | Imported module | Location | Occurrences |
|---|---|---|---:|
| `aivm.attachments.ownership` | `aivm.legacy.pre_0_6_0` | `aivm/attachments/ownership.py` | 1 |
| `aivm.attachments.persistent.manifest` | `aivm.legacy.pre_0_6_0.paths` | `aivm/attachments/persistent/manifest.py` | 1 |
| `aivm.cli.config.lint` | `aivm.legacy.pre_0_6_0` | `aivm/cli/config/lint.py` | 1 |
| `aivm.cli.config.migrate` | `aivm.legacy.pre_0_6_0.cli` | `aivm/cli/config/migrate.py` | 1 |
| `aivm.cli.config.paths` | `aivm.legacy.pre_0_6_0.paths` | `aivm/cli/config/paths.py` | 1 |
| `aivm.config_store.io` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/io.py` | 1 |
| `aivm.config_store.io` | `aivm.legacy.pre_0_6_0.paths` | `aivm/config_store/io.py` | 1 |
| `aivm.config_store.models` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/models.py` | 1 |
| `aivm.config_store.mutate` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/mutate.py` | 1 |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/parse.py` | 1 |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0.schema` | `aivm/config_store/parse.py` | 2 |
| `aivm.config_store.render` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/render.py` | 1 |
| `aivm.credentials.ownership` | `aivm.legacy.pre_0_6_0` | `aivm/credentials/ownership.py` | 1 |
| `aivm.firewall` | `aivm.legacy.pre_0_6_0.firewall` | `aivm/firewall.py` | 1 |
| `aivm.scoped_store` | `aivm.legacy.pre_0_6_0` | `aivm/scoped_store.py` | 1 |
| `aivm.scoped_store` | `aivm.legacy.pre_0_6_0.selection` | `aivm/scoped_store.py` | 1 |
| `aivm.services` | `aivm.legacy.pre_0_6_0.context` | `aivm/services.py` | 1 |
| `aivm.vm.update.virtiofs` | `aivm.legacy.pre_0_6_0` | `aivm/vm/update/virtiofs.py` | 1 |
| `aivm.vm.update.virtiofs` | `aivm.legacy.pre_0_6_0.virtiofsd_wrapper` | `aivm/vm/update/virtiofs.py` | 1 |

## Canonical `AgentVMConfig` references (256)

`ResolvedVMContext.effective_cfg` deliberately carries this aggregate
compatibility view while canonical runtime consumers are narrowed.

| Module | Location | Occurrences |
|---|---|---:|
| `aivm.access_control` | `aivm/access_control.py` | 2 |
| `aivm.attachments.guest` | `aivm/attachments/guest.py` | 9 |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py` | 7 |
| `aivm.attachments.persistent.identity` | `aivm/attachments/persistent/identity.py` | 1 |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py` | 11 |
| `aivm.attachments.persistent.replay` | `aivm/attachments/persistent/replay.py` | 2 |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py` | 4 |
| `aivm.attachments.resolve` | `aivm/attachments/resolve.py` | 2 |
| `aivm.attachments.session` | `aivm/attachments/session.py` | 7 |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py` | 8 |
| `aivm.cli.config.discover` | `aivm/cli/config/discover.py` | 1 |
| `aivm.cli.config.init` | `aivm/cli/config/init.py` | 17 |
| `aivm.cli.config.paths` | `aivm/cli/config/paths.py` | 1 |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py` | 4 |
| `aivm.cli.net` | `aivm/cli/net.py` | 2 |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py` | 7 |
| `aivm.cli.vm_update` | `aivm/cli/vm_update.py` | 1 |
| `aivm.config_review` | `aivm/config_review.py` | 1 |
| `aivm.config_scopes` | `aivm/config_scopes.py` | 4 |
| `aivm.config_store.models` | `aivm/config_store/models.py` | 2 |
| `aivm.config_store.mutate` | `aivm/config_store/mutate.py` | 2 |
| `aivm.config_store.parse` | `aivm/config_store/parse.py` | 2 |
| `aivm.config_store.resolve` | `aivm/config_store/resolve.py` | 1 |
| `aivm.credentials.agent_guest` | `aivm/credentials/agent_guest.py` | 4 |
| `aivm.credentials.guest` | `aivm/credentials/guest.py` | 8 |
| `aivm.credentials.guest_config` | `aivm/credentials/guest_config.py` | 6 |
| `aivm.credentials.service` | `aivm/credentials/service.py` | 5 |
| `aivm.detect` | `aivm/detect.py` | 1 |
| `aivm.enrollment` | `aivm/enrollment.py` | 2 |
| `aivm.firewall` | `aivm/firewall.py` | 8 |
| `aivm.net` | `aivm/net.py` | 3 |
| `aivm.resource_checks` | `aivm/resource_checks.py` | 2 |
| `aivm.scoped_store` | `aivm/scoped_store.py` | 4 |
| `aivm.services` | `aivm/services.py` | 8 |
| `aivm.status` | `aivm/status.py` | 8 |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py` | 5 |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py` | 6 |
| `aivm.vm.create` | `aivm/vm/create.py` | 3 |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py` | 10 |
| `aivm.vm.deletion` | `aivm/vm/deletion.py` | 9 |
| `aivm.vm.disk` | `aivm/vm/disk.py` | 1 |
| `aivm.vm.domain` | `aivm/vm/domain.py` | 5 |
| `aivm.vm.drift` | `aivm/vm/drift.py` | 10 |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py` | 18 |
| `aivm.vm.host_access` | `aivm/vm/host_access.py` | 1 |
| `aivm.vm.images` | `aivm/vm/images.py` | 1 |
| `aivm.vm.paths` | `aivm/vm/paths.py` | 3 |
| `aivm.vm.provision` | `aivm/vm/provision.py` | 2 |
| `aivm.vm.rename` | `aivm/vm/rename.py` | 5 |
| `aivm.vm.share` | `aivm/vm/share.py` | 9 |
| `aivm.vm.update.apply` | `aivm/vm/update/apply.py` | 1 |
| `aivm.vm.update.detect` | `aivm/vm/update/detect.py` | 3 |
| `aivm.vm.update.fdguard` | `aivm/vm/update/fdguard.py` | 3 |
| `aivm.vm.update.render` | `aivm/vm/update/render.py` | 1 |
| `aivm.vm.update.restart` | `aivm/vm/update/restart.py` | 1 |
| `aivm.vm.update.virtiofs` | `aivm/vm/update/virtiofs.py` | 2 |

## Path-based `StoreScope` reconstruction sites (19)

These calls pass a stringified path back into `resolve_store_scope`.
They are reported for visibility and are not yet forbidden.

| Module | Argument | Location | Occurrences |
|---|---|---|---:|
| `aivm.attachments.ownership` | `store_path` | `aivm/attachments/ownership.py` | 1 |
| `aivm.cli.config.init` | `path` | `aivm/cli/config/init.py` | 1 |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py` | 4 |
| `aivm.cli.vm_attach` | `cfg_path` | `aivm/cli/vm_attach.py` | 1 |
| `aivm.cli.vm_creds` | `store_path` | `aivm/cli/vm_creds.py` | 1 |
| `aivm.cli.vm_lifecycle` | `cfg_path` | `aivm/cli/vm_lifecycle.py` | 2 |
| `aivm.cli.vm_lifecycle` | `requested_path` | `aivm/cli/vm_lifecycle.py` | 1 |
| `aivm.credentials.agent` | `store_path` | `aivm/credentials/agent.py` | 1 |
| `aivm.credentials.agent_transport` | `store_path` | `aivm/credentials/agent_transport.py` | 1 |
| `aivm.credentials.service` | `store_path` | `aivm/credentials/service.py` | 1 |
| `aivm.operational_scope` | `path` | `aivm/operational_scope.py` | 1 |
| `aivm.services` | `store_path` | `aivm/services.py` | 1 |
| `aivm.services` | `target` | `aivm/services.py` | 1 |
| `aivm.vm.create` | `config_store_path` | `aivm/vm/create.py` | 1 |
| `aivm.vm.create_ops` | `cfg_path` | `aivm/vm/create_ops.py` | 1 |
