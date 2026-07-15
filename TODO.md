* Rework the user-visible naming and token scheme for attached folders. The
  current names are functional, but the distinction between lexical paths,
  canonical paths, guest destinations, and export tokens is harder to explain
  than it should be.

* Add an autouse test fixture that isolates ``HOME`` and ``XDG_CONFIG_HOME``
  and fails if a test touches the real AIVM config store. Individual CLI tests
  should still pass an explicit temporary ``--config`` path where practical.
