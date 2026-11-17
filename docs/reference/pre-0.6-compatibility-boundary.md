# Pre-0.6 compatibility boundary

AIVM treats compatibility with released versions before 0.6.0 as one
versioned subsystem:

```text
aivm/legacy/pre_0_6_0/
```

The path is intentionally explicit. Any production import from this package is
a dependency on the pre-0.6 support window and should be removable when that
window closes. The matching tests and released fixtures live under:

```text
tests/legacy/pre_0_6_0/
```

Ordinary tests must not import the versioned compatibility package merely as
scaffolding; they construct canonical machine/profile contexts instead.

## Owned implementation

The package owns the bulk of old-version behavior:

- released-store migration planning, apply, resume, verification, and rollback;
- migration CLI implementation;
- synthetic runtime context construction from one aggregate per-user config;
- released per-user config and persistent-state paths;
- released-store selection and fallback rules;
- schema-5 through schema-8 field normalization used by the 0.6 parser;
- cleanup of old un-namespaced firewall tables;
- recognition and cleanup of historical AIVM virtiofsd wrapper paths.

The ordinary CLI registration module remains at
`aivm.cli.config.migrate`, but it only imports command classes from the
versioned package. The old `aivm.migration`, `aivm.migration_apply`, and
`aivm.vm.virtiofsd_wrapper` paths are tiny failure stubs. They contain no
compatibility implementation and exist only because applying an overlay cannot
delete a stale file from an existing checkout.

## Mixed surfaces

Some canonical modules must parse or render both current and released data.
Moving the entire function would make the modern store layer depend on a legacy
facade. These functions and classes import and use:

```python
from aivm.legacy.pre_0_6_0 import compatibility_surface
```

The decorator preserves object identity and execution behavior while attaching
`__aivm_legacy_support__ = "pre_0_6_0"`. It is a searchable semantic marker,
not a substitute for extraction: substantial logic belongs in the versioned
package.

## Removal procedure

After the support window ends:

1. Remove `aivm/legacy/pre_0_6_0/` and the migration CLI registration.
2. Remove all imports of that namespace and every `@compatibility_surface`
   branch marked `pre_0_6_0`.
3. Remove the three old-path failure stubs.
4. Remove `tests/legacy/pre_0_6_0/`, including released-store fixtures.
5. Make machine/profile storage the only scope selected by `scoped_store`.
6. Remove legacy fields from `Store`, and simplify store parsing/rendering to
   the minimum retained schema version.
7. Remove the per-user persistent replay path and historical firewall/wrapper
   cleanup after a separately documented runtime-state grace period.

`tests/legacy/pre_0_6_0/test_boundary.py` prevents the migration implementation
from drifting back into unversioned modules, verifies that deliberately mixed
surfaces remain marked, and rejects compatibility imports from ordinary test
modules.
