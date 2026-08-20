<!-- GENERATED FILE - DO NOT EDIT -->
<!-- generation schema: 1; input digest: 460eadd87b160d5c -->
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
| `aivm.config_store.models` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/models.py:22` |
| `aivm.config_store.mutate` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/mutate.py:14` |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/parse.py:37` |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0.schema` | `aivm/config_store/parse.py:38` |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0.schema` | `aivm/config_store/parse.py:44` |
| `aivm.config_store.render` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/render.py:10` |
| `aivm.credentials.ownership` | `aivm.legacy.pre_0_6_0` | `aivm/credentials/ownership.py:7` |
| `aivm.firewall` | `aivm.legacy.pre_0_6_0.firewall` | `aivm/firewall.py:19` |
| `aivm.scoped_store` | `aivm.legacy.pre_0_6_0` | `aivm/scoped_store.py:39` |
| `aivm.scoped_store` | `aivm.legacy.pre_0_6_0.selection` | `aivm/scoped_store.py:40` |
| `aivm.services` | `aivm.legacy.pre_0_6_0.context` | `aivm/services.py:40` |
| `aivm.vm.update.virtiofs` | `aivm.legacy.pre_0_6_0` | `aivm/vm/update/virtiofs.py:12` |
| `aivm.vm.update.virtiofs` | `aivm.legacy.pre_0_6_0.virtiofsd_wrapper` | `aivm/vm/update/virtiofs.py:12` |

## Canonical `AgentVMConfig` references (255)

`ResolvedVMContext.effective_cfg` deliberately carries this aggregate
compatibility view while canonical runtime consumers are narrowed.

| Module | Location |
|---|---|
| `aivm.access_control` | `aivm/access_control.py:185` |
| `aivm.access_control` | `aivm/access_control.py:191` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:43` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:118` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:183` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:215` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:320` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:370` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:500` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:596` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:634` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:35` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:306` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:409` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:464` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:517` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:550` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:572` |
| `aivm.attachments.persistent.identity` | `aivm/attachments/persistent/identity.py:107` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:65` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:79` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:90` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:118` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:124` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:195` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:220` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:252` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:313` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:327` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:357` |
| `aivm.attachments.persistent.replay` | `aivm/attachments/persistent/replay.py:24` |
| `aivm.attachments.persistent.replay` | `aivm/attachments/persistent/replay.py:72` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:153` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:242` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:366` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:446` |
| `aivm.attachments.resolve` | `aivm/attachments/resolve.py:149` |
| `aivm.attachments.resolve` | `aivm/attachments/resolve.py:269` |
| `aivm.attachments.session` | `aivm/attachments/session.py:115` |
| `aivm.attachments.session` | `aivm/attachments/session.py:146` |
| `aivm.attachments.session` | `aivm/attachments/session.py:165` |
| `aivm.attachments.session` | `aivm/attachments/session.py:234` |
| `aivm.attachments.session` | `aivm/attachments/session.py:305` |
| `aivm.attachments.session` | `aivm/attachments/session.py:553` |
| `aivm.attachments.session` | `aivm/attachments/session.py:602` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:25` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:33` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:73` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:315` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:492` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:533` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:717` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:794` |
| `aivm.cli.config.discover` | `aivm/cli/config/discover.py:85` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:198` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:397` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:409` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:418` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:426` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:434` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:458` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:464` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:513` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:550` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:551` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:594` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:604` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:605` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:650` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:660` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:661` |
| `aivm.cli.config.paths` | `aivm/cli/config/paths.py:271` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:191` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:202` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:490` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:495` |
| `aivm.cli.net` | `aivm/cli/net.py:178` |
| `aivm.cli.net` | `aivm/cli/net.py:201` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:198` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:346` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:543` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:617` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:645` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:683` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:759` |
| `aivm.cli.vm_update` | `aivm/cli/vm_update.py:35` |
| `aivm.config_review` | `aivm/config_review.py:32` |
| `aivm.config_scopes` | `aivm/config_scopes.py:106` |
| `aivm.config_scopes` | `aivm/config_scopes.py:127` |
| `aivm.config_scopes` | `aivm/config_scopes.py:141` |
| `aivm.config_scopes` | `aivm/config_scopes.py:164` |
| `aivm.config_store.models` | `aivm/config_store/models.py:29` |
| `aivm.config_store.models` | `aivm/config_store/models.py:144` |
| `aivm.config_store.mutate` | `aivm/config_store/mutate.py:29` |
| `aivm.config_store.mutate` | `aivm/config_store/mutate.py:36` |
| `aivm.config_store.parse` | `aivm/config_store/parse.py:114` |
| `aivm.config_store.parse` | `aivm/config_store/parse.py:115` |
| `aivm.config_store.resolve` | `aivm/config_store/resolve.py:224` |
| `aivm.credentials.agent_guest` | `aivm/credentials/agent_guest.py:102` |
| `aivm.credentials.agent_guest` | `aivm/credentials/agent_guest.py:160` |
| `aivm.credentials.agent_guest` | `aivm/credentials/agent_guest.py:230` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:62` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:79` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:101` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:124` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:200` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:240` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:302` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:335` |
| `aivm.credentials.guest_config` | `aivm/credentials/guest_config.py:24` |
| `aivm.credentials.guest_config` | `aivm/credentials/guest_config.py:65` |
| `aivm.credentials.guest_config` | `aivm/credentials/guest_config.py:93` |
| `aivm.credentials.guest_config` | `aivm/credentials/guest_config.py:118` |
| `aivm.credentials.guest_config` | `aivm/credentials/guest_config.py:150` |
| `aivm.credentials.guest_config` | `aivm/credentials/guest_config.py:194` |
| `aivm.credentials.service` | `aivm/credentials/service.py:174` |
| `aivm.credentials.service` | `aivm/credentials/service.py:347` |
| `aivm.credentials.service` | `aivm/credentials/service.py:504` |
| `aivm.credentials.service` | `aivm/credentials/service.py:597` |
| `aivm.credentials.service` | `aivm/credentials/service.py:738` |
| `aivm.detect` | `aivm/detect.py:297` |
| `aivm.enrollment` | `aivm/enrollment.py:264` |
| `aivm.enrollment` | `aivm/enrollment.py:315` |
| `aivm.firewall` | `aivm/firewall.py:29` |
| `aivm.firewall` | `aivm/firewall.py:77` |
| `aivm.firewall` | `aivm/firewall.py:140` |
| `aivm.firewall` | `aivm/firewall.py:208` |
| `aivm.firewall` | `aivm/firewall.py:280` |
| `aivm.firewall` | `aivm/firewall.py:446` |
| `aivm.firewall` | `aivm/firewall.py:477` |
| `aivm.firewall` | `aivm/firewall.py:648` |
| `aivm.net` | `aivm/net.py:50` |
| `aivm.net` | `aivm/net.py:181` |
| `aivm.net` | `aivm/net.py:242` |
| `aivm.resource_checks` | `aivm/resource_checks.py:62` |
| `aivm.resource_checks` | `aivm/resource_checks.py:99` |
| `aivm.scoped_store` | `aivm/scoped_store.py:245` |
| `aivm.scoped_store` | `aivm/scoped_store.py:269` |
| `aivm.scoped_store` | `aivm/scoped_store.py:289` |
| `aivm.scoped_store` | `aivm/scoped_store.py:343` |
| `aivm.services` | `aivm/services.py:81` |
| `aivm.services` | `aivm/services.py:110` |
| `aivm.services` | `aivm/services.py:402` |
| `aivm.services` | `aivm/services.py:447` |
| `aivm.services` | `aivm/services.py:458` |
| `aivm.services` | `aivm/services.py:467` |
| `aivm.services` | `aivm/services.py:495` |
| `aivm.services` | `aivm/services.py:532` |
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
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:331` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:28` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:71` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:80` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:245` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:283` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:296` |
| `aivm.vm.create` | `aivm/vm/create.py:34` |
| `aivm.vm.create` | `aivm/vm/create.py:151` |
| `aivm.vm.create` | `aivm/vm/create.py:190` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:71` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:83` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:92` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:99` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:168` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:169` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:223` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:243` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:292` |
| `aivm.vm.create_ops` | `aivm/vm/create_ops.py:336` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:147` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:154` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:268` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:279` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:339` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:395` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:415` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:537` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:680` |
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
| `aivm.vm.provision` | `aivm/vm/provision.py:23` |
| `aivm.vm.provision` | `aivm/vm/provision.py:102` |
| `aivm.vm.rename` | `aivm/vm/rename.py:68` |
| `aivm.vm.rename` | `aivm/vm/rename.py:96` |
| `aivm.vm.rename` | `aivm/vm/rename.py:126` |
| `aivm.vm.rename` | `aivm/vm/rename.py:260` |
| `aivm.vm.rename` | `aivm/vm/rename.py:378` |
| `aivm.vm.share` | `aivm/vm/share.py:194` |
| `aivm.vm.share` | `aivm/vm/share.py:262` |
| `aivm.vm.share` | `aivm/vm/share.py:285` |
| `aivm.vm.share` | `aivm/vm/share.py:314` |
| `aivm.vm.share` | `aivm/vm/share.py:346` |
| `aivm.vm.share` | `aivm/vm/share.py:356` |
| `aivm.vm.share` | `aivm/vm/share.py:370` |
| `aivm.vm.share` | `aivm/vm/share.py:496` |
| `aivm.vm.share` | `aivm/vm/share.py:560` |
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

## Path-based `StoreScope` reconstruction sites (19)

These calls pass a stringified path back into `resolve_store_scope`.
They are reported for visibility and are not yet forbidden.

| Module | Argument | Location |
|---|---|---|
| `aivm.attachments.ownership` | `store_path` | `aivm/attachments/ownership.py:27` |
| `aivm.cli.config.init` | `path` | `aivm/cli/config/init.py:125` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:39` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:107` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:143` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:208` |
| `aivm.cli.vm_attach` | `cfg_path` | `aivm/cli/vm_attach.py:801` |
| `aivm.cli.vm_creds` | `store_path` | `aivm/cli/vm_creds.py:105` |
| `aivm.cli.vm_lifecycle` | `requested_path` | `aivm/cli/vm_lifecycle.py:225` |
| `aivm.cli.vm_lifecycle` | `cfg_path` | `aivm/cli/vm_lifecycle.py:236` |
| `aivm.cli.vm_lifecycle` | `cfg_path` | `aivm/cli/vm_lifecycle.py:354` |
| `aivm.credentials.agent` | `store_path` | `aivm/credentials/agent.py:66` |
| `aivm.credentials.agent_transport` | `store_path` | `aivm/credentials/agent_transport.py:56` |
| `aivm.credentials.service` | `store_path` | `aivm/credentials/service.py:74` |
| `aivm.operational_scope` | `path` | `aivm/operational_scope.py:33` |
| `aivm.services` | `store_path` | `aivm/services.py:353` |
| `aivm.services` | `target` | `aivm/services.py:473` |
| `aivm.vm.create` | `config_store_path` | `aivm/vm/create.py:229` |
| `aivm.vm.create_ops` | `cfg_path` | `aivm/vm/create_ops.py:248` |
