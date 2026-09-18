# OpenBSD `pfctl` smoke test

Status: **implemented but not yet executed in the Gatehold OpenBSD lab**

The normal Linux CI uses a controlled substitute for `pfctl`. Gatehold also
contains an opt-in test that stages a minimal default-deny candidate and invokes
the real `/sbin/pfctl -nf`. The `-n` option performs syntax checking without
loading the candidate ruleset.

On an OpenBSD development VM with the required compiler and CMake tooling:

```console
cmake -S . -B build-openbsd \
  -DCMAKE_BUILD_TYPE=Debug \
  -DGATEHOLD_WARNINGS_AS_ERRORS=ON \
  -DGATEHOLD_ENABLE_OPENBSD_PF_TESTS=ON
cmake --build build-openbsd --parallel
doas ctest --test-dir build-openbsd \
  -R gatehold.openbsd.pfctl_smoke \
  --output-on-failure -V
```

The build deliberately rejects `GATEHOLD_ENABLE_OPENBSD_PF_TESTS=ON` on a
non-OpenBSD system. The test creates only private temporary files, runs native
syntax validation, and removes its temporary directory. It does not execute
`pfctl -f` and does not replace the active PF ruleset.

Record the OpenBSD release, architecture, compiler, CMake version, test output,
and Gatehold commit when reporting the first native run.

