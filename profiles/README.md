# Declarative browser profiles

Files under `profiles/` are the reviewable source for generated native
`struct impersonate_opts` initializers. A profile contains typed native options
and capture provenance; generated C is never edited by hand.

Render a profile from the repository root:

```sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest render profiles/chrome/chrome146.json
```

Create a candidate only from an authoritative, ready capture bundle:

```sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest candidate \
  captures/stable/VERSION/PLATFORM \
  --target chromeVERSION \
  --output profiles/chrome/chromeVERSION.json
```

`chrome146.json` is a legacy import that must render exactly to the existing
initializer in `patches/curl.patch`. New profiles must point to a retained
consumer-browser capture bundle and pass native replay verification before
release.

The CMake superbuild injects all `profiles/generated/*.inc` files after applying
the maintained curl patch. Generated target names must be unique and cannot
replace a target already supplied by that patch.

Readiness also rejects Chrome behavior that the current native connection paths
cannot express independently. A generated profile is published only after a
native build and replay match the retained browser evidence.

Desktop Chrome majors expose explicit `_linux`, `_windows`, and `_macos`
targets because their default headers and client hints differ even when their
TLS, HTTP/2, HTTP/3, and QUIC transport behavior is identical. The unsuffixed
target is retained as the macOS-compatible default.
