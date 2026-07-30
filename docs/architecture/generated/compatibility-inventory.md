<!-- GENERATED FILE - DO NOT EDIT -->
<!-- generation schema: 1; input digest: 1a0f25bec2ae0ceb -->
# Compatibility and transitional architecture inventory

This inventory is observational. The legacy-import allowlist is enforced;
the aggregate-config and scope-reconstruction lists are intended to shrink.

## Canonical imports of `aivm.legacy.pre_0_6_0` (19)

| Importer | Imported module | Location |
|---|---|---|
| `aivm.attachments.ownership` | `aivm.legacy.pre_0_6_0` | `aivm/attachments/ownership.py:14` |
| `aivm.attachments.persistent.manifest` | `aivm.legacy.pre_0_6_0.paths` | `aivm/attachments/persistent/manifest.py:26` |
| `aivm.cli.config.lint` | `aivm.legacy.pre_0_6_0` | `aivm/cli/config/lint.py:11` |
| `aivm.cli.config.migrate` | `aivm.legacy.pre_0_6_0.cli` | `aivm/cli/config/migrate.py:3` |
| `aivm.cli.config.paths` | `aivm.legacy.pre_0_6_0.paths` | `aivm/cli/config/paths.py:19` |
| `aivm.config_store.io` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/io.py:39` |
| `aivm.config_store.io` | `aivm.legacy.pre_0_6_0.paths` | `aivm/config_store/io.py:40` |
| `aivm.config_store.models` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/models.py:13` |
| `aivm.config_store.mutate` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/mutate.py:8` |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/parse.py:28` |
| `aivm.config_store.parse` | `aivm.legacy.pre_0_6_0.schema` | `aivm/config_store/parse.py:29` |
| `aivm.config_store.render` | `aivm.legacy.pre_0_6_0` | `aivm/config_store/render.py:9` |
| `aivm.credentials.ownership` | `aivm.legacy.pre_0_6_0` | `aivm/credentials/ownership.py:6` |
| `aivm.firewall` | `aivm.legacy.pre_0_6_0.firewall` | `aivm/firewall.py:19` |
| `aivm.scoped_store` | `aivm.legacy.pre_0_6_0` | `aivm/scoped_store.py:41` |
| `aivm.scoped_store` | `aivm.legacy.pre_0_6_0.selection` | `aivm/scoped_store.py:42` |
| `aivm.services` | `aivm.legacy.pre_0_6_0.context` | `aivm/services.py:25` |
| `aivm.vm.update.virtiofs` | `aivm.legacy.pre_0_6_0` | `aivm/vm/update/virtiofs.py:15` |
| `aivm.vm.update.virtiofs` | `aivm.legacy.pre_0_6_0.virtiofsd_wrapper` | `aivm/vm/update/virtiofs.py:15` |

## Canonical `AgentVMConfig` references (238)

`ResolvedVMContext.effective_cfg` deliberately carries this aggregate
compatibility view while canonical runtime consumers are narrowed.

| Module | Location |
|---|---|
| `aivm.access_control` | `aivm/access_control.py:185` |
| `aivm.access_control` | `aivm/access_control.py:191` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:41` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:113` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:227` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:273` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:403` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:499` |
| `aivm.attachments.guest` | `aivm/attachments/guest.py:537` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:25` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:67` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:108` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:163` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:216` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:235` |
| `aivm.attachments.persistent.host_bind` | `aivm/attachments/persistent/host_bind.py:257` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:64` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:78` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:89` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:116` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:122` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:193` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:218` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:250` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:311` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:325` |
| `aivm.attachments.persistent.manifest` | `aivm/attachments/persistent/manifest.py:355` |
| `aivm.attachments.persistent.replay` | `aivm/attachments/persistent/replay.py:22` |
| `aivm.attachments.persistent.replay` | `aivm/attachments/persistent/replay.py:70` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:151` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:247` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:370` |
| `aivm.attachments.persistent.transport` | `aivm/attachments/persistent/transport.py:450` |
| `aivm.attachments.resolve` | `aivm/attachments/resolve.py:141` |
| `aivm.attachments.resolve` | `aivm/attachments/resolve.py:222` |
| `aivm.attachments.session` | `aivm/attachments/session.py:115` |
| `aivm.attachments.session` | `aivm/attachments/session.py:146` |
| `aivm.attachments.session` | `aivm/attachments/session.py:165` |
| `aivm.attachments.session` | `aivm/attachments/session.py:226` |
| `aivm.attachments.session` | `aivm/attachments/session.py:297` |
| `aivm.attachments.session` | `aivm/attachments/session.py:530` |
| `aivm.attachments.session` | `aivm/attachments/session.py:576` |
| `aivm.attachments.session` | `aivm/attachments/session.py:608` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:24` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:32` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:72` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:314` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:491` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:532` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:716` |
| `aivm.attachments.shared_root` | `aivm/attachments/shared_root.py:793` |
| `aivm.cli.config.discover` | `aivm/cli/config/discover.py:84` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:142` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:341` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:353` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:362` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:370` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:378` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:402` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:408` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:457` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:494` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:495` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:538` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:548` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:549` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:594` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:604` |
| `aivm.cli.config.init` | `aivm/cli/config/init.py:605` |
| `aivm.cli.config.paths` | `aivm/cli/config/paths.py:271` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:187` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:198` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:486` |
| `aivm.cli.host_permissions` | `aivm/cli/host_permissions.py:491` |
| `aivm.cli.net` | `aivm/cli/net.py:173` |
| `aivm.cli.net` | `aivm/cli/net.py:196` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:188` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:259` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:329` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:466` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:540` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:568` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:606` |
| `aivm.cli.vm_attach` | `aivm/cli/vm_attach.py:682` |
| `aivm.cli.vm_update` | `aivm/cli/vm_update.py:35` |
| `aivm.config_review` | `aivm/config_review.py:32` |
| `aivm.config_scopes` | `aivm/config_scopes.py:102` |
| `aivm.config_scopes` | `aivm/config_scopes.py:123` |
| `aivm.config_scopes` | `aivm/config_scopes.py:137` |
| `aivm.config_scopes` | `aivm/config_scopes.py:159` |
| `aivm.config_store.models` | `aivm/config_store/models.py:28` |
| `aivm.config_store.models` | `aivm/config_store/models.py:102` |
| `aivm.config_store.mutate` | `aivm/config_store/mutate.py:21` |
| `aivm.config_store.mutate` | `aivm/config_store/mutate.py:28` |
| `aivm.config_store.parse` | `aivm/config_store/parse.py:57` |
| `aivm.config_store.parse` | `aivm/config_store/parse.py:58` |
| `aivm.config_store.resolve` | `aivm/config_store/resolve.py:224` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:60` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:77` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:99` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:122` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:198` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:238` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:300` |
| `aivm.credentials.guest` | `aivm/credentials/guest.py:333` |
| `aivm.credentials.service` | `aivm/credentials/service.py:174` |
| `aivm.credentials.service` | `aivm/credentials/service.py:347` |
| `aivm.credentials.service` | `aivm/credentials/service.py:504` |
| `aivm.credentials.service` | `aivm/credentials/service.py:583` |
| `aivm.credentials.service` | `aivm/credentials/service.py:717` |
| `aivm.detect` | `aivm/detect.py:297` |
| `aivm.enrollment` | `aivm/enrollment.py:257` |
| `aivm.enrollment` | `aivm/enrollment.py:286` |
| `aivm.firewall` | `aivm/firewall.py:29` |
| `aivm.firewall` | `aivm/firewall.py:77` |
| `aivm.firewall` | `aivm/firewall.py:140` |
| `aivm.firewall` | `aivm/firewall.py:208` |
| `aivm.firewall` | `aivm/firewall.py:280` |
| `aivm.firewall` | `aivm/firewall.py:311` |
| `aivm.firewall` | `aivm/firewall.py:482` |
| `aivm.net` | `aivm/net.py:50` |
| `aivm.net` | `aivm/net.py:181` |
| `aivm.net` | `aivm/net.py:238` |
| `aivm.resource_checks` | `aivm/resource_checks.py:62` |
| `aivm.resource_checks` | `aivm/resource_checks.py:99` |
| `aivm.scoped_store` | `aivm/scoped_store.py:232` |
| `aivm.scoped_store` | `aivm/scoped_store.py:256` |
| `aivm.scoped_store` | `aivm/scoped_store.py:276` |
| `aivm.scoped_store` | `aivm/scoped_store.py:330` |
| `aivm.services` | `aivm/services.py:80` |
| `aivm.services` | `aivm/services.py:109` |
| `aivm.services` | `aivm/services.py:397` |
| `aivm.services` | `aivm/services.py:442` |
| `aivm.services` | `aivm/services.py:453` |
| `aivm.services` | `aivm/services.py:462` |
| `aivm.services` | `aivm/services.py:490` |
| `aivm.services` | `aivm/services.py:527` |
| `aivm.status` | `aivm/status.py:140` |
| `aivm.status` | `aivm/status.py:271` |
| `aivm.status` | `aivm/status.py:323` |
| `aivm.status` | `aivm/status.py:391` |
| `aivm.status` | `aivm/status.py:488` |
| `aivm.status` | `aivm/status.py:515` |
| `aivm.status` | `aivm/status.py:572` |
| `aivm.status` | `aivm/status.py:613` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:61` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:65` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:78` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:117` |
| `aivm.vm.cloudinit` | `aivm/vm/cloudinit.py:330` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:26` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:67` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:76` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:237` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:267` |
| `aivm.vm.connectivity` | `aivm/vm/connectivity.py:280` |
| `aivm.vm.create` | `aivm/vm/create.py:28` |
| `aivm.vm.create` | `aivm/vm/create.py:145` |
| `aivm.vm.create` | `aivm/vm/create.py:184` |
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
| `aivm.vm.deletion` | `aivm/vm/deletion.py:145` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:152` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:266` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:277` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:337` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:393` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:411` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:513` |
| `aivm.vm.deletion` | `aivm/vm/deletion.py:656` |
| `aivm.vm.disk` | `aivm/vm/disk.py:19` |
| `aivm.vm.domain` | `aivm/vm/domain.py:266` |
| `aivm.vm.domain` | `aivm/vm/domain.py:390` |
| `aivm.vm.domain` | `aivm/vm/domain.py:473` |
| `aivm.vm.domain` | `aivm/vm/domain.py:597` |
| `aivm.vm.domain` | `aivm/vm/domain.py:621` |
| `aivm.vm.drift` | `aivm/vm/drift.py:56` |
| `aivm.vm.drift` | `aivm/vm/drift.py:194` |
| `aivm.vm.drift` | `aivm/vm/drift.py:231` |
| `aivm.vm.drift` | `aivm/vm/drift.py:252` |
| `aivm.vm.drift` | `aivm/vm/drift.py:301` |
| `aivm.vm.drift` | `aivm/vm/drift.py:320` |
| `aivm.vm.drift` | `aivm/vm/drift.py:414` |
| `aivm.vm.drift` | `aivm/vm/drift.py:542` |
| `aivm.vm.drift` | `aivm/vm/drift.py:616` |
| `aivm.vm.drift` | `aivm/vm/drift.py:650` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:16` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:53` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:161` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:206` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:264` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:309` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:352` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:481` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:491` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:497` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:501` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:505` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:509` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:513` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:517` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:522` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:529` |
| `aivm.vm.guest_tools` | `aivm/vm/guest_tools.py:538` |
| `aivm.vm.host_access` | `aivm/vm/host_access.py:260` |
| `aivm.vm.images` | `aivm/vm/images.py:162` |
| `aivm.vm.paths` | `aivm/vm/paths.py:10` |
| `aivm.vm.paths` | `aivm/vm/paths.py:26` |
| `aivm.vm.paths` | `aivm/vm/paths.py:36` |
| `aivm.vm.provision` | `aivm/vm/provision.py:19` |
| `aivm.vm.share` | `aivm/vm/share.py:179` |
| `aivm.vm.share` | `aivm/vm/share.py:247` |
| `aivm.vm.share` | `aivm/vm/share.py:270` |
| `aivm.vm.share` | `aivm/vm/share.py:299` |
| `aivm.vm.share` | `aivm/vm/share.py:331` |
| `aivm.vm.share` | `aivm/vm/share.py:341` |
| `aivm.vm.share` | `aivm/vm/share.py:355` |
| `aivm.vm.share` | `aivm/vm/share.py:477` |
| `aivm.vm.share` | `aivm/vm/share.py:540` |
| `aivm.vm.update.apply` | `aivm/vm/update/apply.py:46` |
| `aivm.vm.update.detect` | `aivm/vm/update/detect.py:25` |
| `aivm.vm.update.detect` | `aivm/vm/update/detect.py:73` |
| `aivm.vm.update.detect` | `aivm/vm/update/detect.py:88` |
| `aivm.vm.update.fdguard` | `aivm/vm/update/fdguard.py:36` |
| `aivm.vm.update.fdguard` | `aivm/vm/update/fdguard.py:60` |
| `aivm.vm.update.fdguard` | `aivm/vm/update/fdguard.py:178` |
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
| `aivm.cli.config.init` | `path` | `aivm/cli/config/init.py:114` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:39` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:106` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:140` |
| `aivm.cli.vm_access` | `path` | `aivm/cli/vm_access.py:204` |
| `aivm.cli.vm_attach` | `cfg_path` | `aivm/cli/vm_attach.py:724` |
| `aivm.cli.vm_creds` | `store_path` | `aivm/cli/vm_creds.py:66` |
| `aivm.cli.vm_lifecycle` | `requested_path` | `aivm/cli/vm_lifecycle.py:203` |
| `aivm.cli.vm_lifecycle` | `cfg_path` | `aivm/cli/vm_lifecycle.py:214` |
| `aivm.credentials.service` | `store_path` | `aivm/credentials/service.py:74` |
| `aivm.operational_scope` | `path` | `aivm/operational_scope.py:33` |
| `aivm.services` | `store_path` | `aivm/services.py:352` |
| `aivm.services` | `target` | `aivm/services.py:468` |
| `aivm.vm.create` | `config_store_path` | `aivm/vm/create.py:213` |
| `aivm.vm.create_ops` | `cfg_path` | `aivm/vm/create_ops.py:248` |
