<!-- GENERATED FILE - DO NOT EDIT -->
<!-- generation schema: 1; input digest: 72563be221f09cbe -->
# Compatibility and transitional architecture inventory

This inventory is observational. The legacy-import allowlist is enforced;
the aggregate-config and scope-reconstruction lists are intended to shrink.

## Canonical imports of `aivm.legacy.pre_0_6_0` (20)

| Importer | Imported module | Location |
|---|---|---|
| `aivm.attachments.ownership` | `aivm.legacy.pre_0_6_0` | `aivm/attachments/ownership.py:15` |
| `aivm.attachments.persistent.manifest` | `aivm.legacy.pre_0_6_0.paths` | `aivm/attachments/persistent/manifest.py:28` |
| `aivm.cli.config.lint` | `aivm.legacy.pre_0_6_0` | `aivm/cli/config/lint.py:34` |
| `aivm.cli.config.migrate` | `aivm.legacy.pre_0_6_0.cli` | `aivm/cli/config/migrate.py:3` |
| `aivm.cli.config.paths` | `aivm.legacy.pre_0_6_0.paths` | `aivm/cli/config/paths.py:20` |
| `aivm.config_store.io` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/io.py:31` |
| `aivm.config_store.io` | `aivm.legacy.pre_0_6_0.paths` | `aivm/config_store/io.py:32` |
| `aivm.config_store.models` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/models.py:21` |
| `aivm.config_store.mutate` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/mutate.py:9` |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/parse.py:28` |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0.schema` | `aivm/config_store/parse.py:29` |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0.schema` | `aivm/config_store/parse.py:35` |
| `aivm.config_store.render` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/render.py:9` |
| `aivm.credentials.ownership` | `aivm.legacy.pre_0_6_0` | `aivm/credentials/ownership.py:7` |
| `aivm.firewall` | `aivm.legacy.pre_0_6_0.firewall` | `aivm/firewall.py:19` |
| `aivm.scoped_store` | `aivm.legacy.pre_0_6_0` | `aivm/scoped_store.py:39` |
| `aivm.scoped_store` | `aivm.legacy.pre_0_6_0.selection` | `aivm/scoped_store.py:40` |
| `aivm.services` | `aivm.legacy.pre_0_6_0.context` | `aivm/services.py:39` |
| `aivm.vm.update.virtiofs` | `aivm.legacy.pre_0_6_0` | `aivm/vm/update/virtiofs.py:12` |
| `aivm.vm.update.virtiofs` | `aivm.legacy.pre_0_6_0.virtiofsd_wrapper` | `aivm/vm/update/virtiofs.py:12` |

## Canonical `AgentVMConfig` references (238)

`ResolvedVMContext.effective_cfg` deliberately carries this aggregate
compatibility view while canonical runtime consumers are narrowed.

| Module | Location |
|---|---|
| `aivm.access_control` | `aivm/access_control.py:185` |
| `aivm.access_control` | `aivm/access_control.py:191` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:42` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:114` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:229` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:275` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:405` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:501` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:539` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:32` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:168` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:224` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:279` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:332` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:351` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:373` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:65` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:79` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:90` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:117` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:123` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:194` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:219` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:251` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:312` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:326` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:356` |
| `aivm.attachments.persistent.replay` | `aivm/attachments/persistent/replay.py:23` |
| `aivm.attachments.persistent.replay` | `aivm/attachments/persistent/replay.py:71` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:152` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:248` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:371` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:451` |
| `aivm.attachments.resolve` | `aivm/attachments/resolve.py:145` |
| `aivm.attachments.resolve` | `aivm/attachments/resolve.py:265` |
| `aivm.attachments.session` | `aivm/attachments/session.py:113` |
| `aivm.attachments.session` | `aivm/attachments/session.py:144` |
| `aivm.attachments.session` | `aivm/attachments/session.py:163` |
| `aivm.attachments.session` | `aivm/attachments/session.py:224` |
| `aivm.attachments.session` | `aivm/attachments/session.py:295` |
| `aivm.attachments.session` | `aivm/attachments/session.py:528` |
| `aivm.attachments.session` | `aivm/attachments/session.py:577` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:25` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:33` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:73` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:315` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:492` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:533` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:717` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:794` |
| `aivm.cli.config.discover` | `aivm/cli/config/discover.py:84` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:197` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:396` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:408` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:417` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:425` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:433` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:457` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:463` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:512` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:549` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:550` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:593` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:603` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:604` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:649` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:659` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:660` |
| `aivm.cli.config.paths` | `aivm/cli/config/paths.py:271` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:187` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:198` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:486` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:491` |
| `aivm.cli.net` | `aivm/cli/net.py:173` |
| `aivm.cli.net` | `aivm/cli/net.py:196` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:190` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:261` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:331` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:520` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:594` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:622` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:660` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:736` |
| `aivm.cli.vm_update` | `aivm/cli/vm_update.py:35` |
| `aivm.config_review` | `aivm/config_review.py:32` |
| `aivm.config_scopes` | `aivm/config_scopes.py:102` |
| `aivm.config_scopes` | `aivm/config_scopes.py:123` |
| `aivm.config_scopes` | `aivm/config_scopes.py:137` |
| `aivm.config_scopes` | `aivm/config_scopes.py:159` |
| `aivm.config_store.models` | `aivm/config_store/models.py:28` |
| `aivm.config_store.models` | `aivm/config_store/models.py:116` |
| `aivm.config_store.mutate` | `aivm/config_store/mutate.py:22` |
| `aivm.config_store.mutate` | `aivm/config_store/mutate.py:29` |
| `aivm.config_store.parse` | `aivm/config_store/parse.py:107` |
| `aivm.config_store.parse` | `aivm/config_store/parse.py:108` |
| `aivm.config_store.resolve` | `aivm/config_store/resolve.py:224` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:62` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:79` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:101` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:124` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:200` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:240` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:302` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:335` |
| `aivm.credentials.service` | `aivm/credentials/service.py:174` |
| `aivm.credentials.service` | `aivm/credentials/service.py:347` |
| `aivm.credentials.service` | `aivm/credentials/service.py:504` |
| `aivm.credentials.service` | `aivm/credentials/service.py:583` |
| `aivm.credentials.service` | `aivm/credentials/service.py:717` |
| `aivm.detect` | `aivm/detect.py:297` |
| `aivm.enrollment` | `aivm/enrollment.py:257` |
| `aivm.enrollment` | `aivm/enrollment.py:308` |
| `aivm.firewall` | `aivm/firewall.py:29` |
| `aivm.firewall` | `aivm/firewall.py:77` |
| `aivm.firewall` | `aivm/firewall.py:140` |
| `aivm.firewall` | `aivm/firewall.py:208` |
| `aivm.firewall` | `aivm/firewall.py:280` |
| `aivm.firewall` | `aivm/firewall.py:444` |
| `aivm.firewall` | `aivm/firewall.py:475` |
| `aivm.firewall` | `aivm/firewall.py:646` |
| `aivm.net` | `aivm/net.py:50` |
| `aivm.net` | `aivm/net.py:181` |
| `aivm.net` | `aivm/net.py:242` |
| `aivm.resource_checks` | `aivm/resource_checks.py:62` |
| `aivm.resource_checks` | `aivm/resource_checks.py:99` |
| `aivm.scoped_store` | `aivm/scoped_store.py:230` |
| `aivm.scoped_store` | `aivm/scoped_store.py:254` |
| `aivm.scoped_store` | `aivm/scoped_store.py:274` |
| `aivm.scoped_store` | `aivm/scoped_store.py:328` |
| `aivm.services` | `aivm/services.py:80` |
| `aivm.services` | `aivm/services.py:109` |
| `aivm.services` | `aivm/services.py:397` |
| `aivm.services` | `aivm/services.py:442` |
| `aivm.services` | `aivm/services.py:453` |
| `aivm.services` | `aivm/services.py:462` |
| `aivm.services` | `aivm/services.py:490` |
| `aivm.services` | `aivm/services.py:527` |
| `aivm.status` | `aivm/status.py:141` |
| `aivm.status` | `aivm/status.py:272` |
| `aivm.status` | `aivm/status.py:325` |
| `aivm.status` | `aivm/status.py:422` |
| `aivm.status` | `aivm/status.py:517` |
| `aivm.status` | `aivm/status.py:544` |
| `aivm.status` | `aivm/status.py:601` |
| `aivm.status` | `aivm/status.py:642` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:61` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:65` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:78` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:117` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:330` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:28` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:71` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:80` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:243` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:273` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:286` |
| `aivm.vm.create` | `aivm/vm/create.py:34` |
| `aivm.vm.create` | `aivm/vm/create.py:151` |
| `aivm.vm.create` | `aivm/vm/create.py:190` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:70` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:82` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:91` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:98` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:167` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:168` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:222` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:242` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:291` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:335` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:147` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:154` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:268` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:279` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:339` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:395` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:415` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:528` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:671` |
| `aivm.vm.disk` | `aivm/vm/disk.py:19` |
| `aivm.vm.domain` | `aivm/vm/domain.py:90` |
| `aivm.vm.domain` | `aivm/vm/domain.py:313` |
| `aivm.vm.domain` | `aivm/vm/domain.py:440` |
| `aivm.vm.domain` | `aivm/vm/domain.py:523` |
| `aivm.vm.domain` | `aivm/vm/domain.py:646` |
| `aivm.vm.drift` | `aivm/vm/drift.py:57` |
| `aivm.vm.drift` | `aivm/vm/drift.py:195` |
| `aivm.vm.drift` | `aivm/vm/drift.py:234` |
| `aivm.vm.drift` | `aivm/vm/drift.py:255` |
| `aivm.vm.drift` | `aivm/vm/drift.py:304` |
| `aivm.vm.drift` | `aivm/vm/drift.py:323` |
| `aivm.vm.drift` | `aivm/vm/drift.py:417` |
| `aivm.vm.drift` | `aivm/vm/drift.py:545` |
| `aivm.vm.drift` | `aivm/vm/drift.py:619` |
| `aivm.vm.drift` | `aivm/vm/drift.py:653` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:17` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:67` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:175` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:222` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:280` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:325` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:368` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:497` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:507` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:513` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:517` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:521` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:525` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:529` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:533` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:538` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:545` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:554` |
| `aivm.vm.host_access` | `aivm/vm/host_access.py:260` |
| `aivm.vm.images` | `aivm/vm/images.py:162` |
| `aivm.vm.paths` | `aivm/vm/paths.py:10` |
| `aivm.vm.paths` | `aivm/vm/paths.py:26` |
| `aivm.vm.paths` | `aivm/vm/paths.py:36` |
| `aivm.vm.provision` | `aivm/vm/provision.py:20` |
| `aivm.vm.share` | `aivm/vm/share.py:190` |
| `aivm.vm.share` | `aivm/vm/share.py:258` |
| `aivm.vm.share` | `aivm/vm/share.py:281` |
| `aivm.vm.share` | `aivm/vm/share.py:310` |
| `aivm.vm.share` | `aivm/vm/share.py:342` |
| `aivm.vm.share` | `aivm/vm/share.py:352` |
| `aivm.vm.share` | `aivm/vm/share.py:366` |
| `aivm.vm.share` | `aivm/vm/share.py:492` |
| `aivm.vm.share` | `aivm/vm/share.py:556` |
| `aivm.vm.update.apply` | `aivm/vm/update/apply.py:46` |
| `aivm.vm.update.detect` | `aivm/vm/update/detect.py:25` |
| `aivm.vm.update.detect` | `aivm/vm/update/detect.py:73` |
| `aivm.vm.update.detect` | `aivm/vm/update/detect.py:89` |
| `aivm.vm.update.fdguard` | `aivm/vm/update/fdguard.py:37` |
| `aivm.vm.update.fdguard` | `aivm/vm/update/fdguard.py:61` |
| `aivm.vm.update.fdguard` | `aivm/vm/update/fdguard.py:179` |
| `aivm.vm.update.render` | `aivm/vm/update/render.py:10` |
| `aivm.vm.update.restart` | `aivm/vm/update/restart.py:15` |
| `aivm.vm.update.virtiofs` | `aivm/vm/update/virtiofs.py:20` |
| `aivm.vm.update.virtiofs` | `aivm/vm/update/virtiofs.py:71` |

## Path-based `StoreScope` reconstruction sites (16)

These calls pass a stringified path back into `resolve_store_scope`.
They are reported for visibility and are not yet forbidden.

| Module | Argument | Location |
|---|---|---|
| `aivm.attachments.ownership` | `store_path` | `aivm/attachments/ownership.py:27` |
| `aivm.cli.config.init` | `path` | `aivm/cli/config/init.py:124` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:39` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:106` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:140` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:204` |
| `aivm.cli.vm_attach` | `cfg_path` | `aivm/cli/vm_attach.py:778` |
| `aivm.cli.vm_creds` | `store_path` | `aivm/cli/vm_creds.py:66` |
| `aivm.cli.vm_lifecycle` | `requested_path` | `aivm/cli/vm_lifecycle.py:215` |
| `aivm.cli.vm_lifecycle` | `cfg_path` | `aivm/cli/vm_lifecycle.py:226` |
| `aivm.credentials.service` | `store_path` | `aivm/credentials/service.py:74` |
| `aivm.operational_scope` | `path` | `aivm/operational_scope.py:33` |
| `aivm.services` | `store_path` | `aivm/services.py:352` |
| `aivm.services` | `target` | `aivm/services.py:468` |
| `aivm.vm.create` | `config_store_path` | `aivm/vm/create.py:229` |
| `aivm.vm.create_ops` | `cfg_path` | `aivm/vm/create_ops.py:247` |
