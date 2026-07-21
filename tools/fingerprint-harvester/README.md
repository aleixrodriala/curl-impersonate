# Browser fingerprint harvester

This standalone developer tool captures consumer Chrome and Safari TLS,
HTTP/2, HTTP/3, QUIC, and navigation-header behavior. It normalizes connection
randomness, validates whether the native fork can represent every observed
field, and compiles ready evidence into a declarative native profile.

Playwright is used only as a CDP client. TLS/HTTP2 is the initial Chrome
command-line navigation, and HTTP/3 is opened by a second Chrome command in the
same fresh running profile. CDP never initiates either measured request, and
Playwright does not launch or configure the measured browser.

## Setup

From the repository root:

~~~sh
uv sync --project tools/fingerprint-harvester --extra dev
~~~

This installs the Playwright client and driver. It does not download a
Playwright-managed browser; captures use installed consumer Google Chrome or an
explicit --chrome-binary.

## Consumer Stable capture

Chrome Stable rollout is platform-specific. Query the official
VersionHistory API separately for each target:

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest release --platform linux

uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest release --platform win64
~~~

Supported desktop platform identifiers are linux, win64, mac, and mac_arm64.

Capture five fresh headful profiles from installed Chrome:

~~~sh
xvfb-run -a uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest harvest \
  --platform linux \
  --browser-mode headful \
  --samples 5 \
  --workspace .cache/fingerprint-harvester
~~~

The immutable bundle path is:

~~~text
WORKSPACE/captures/CHANNEL/VERSION/PLATFORM
~~~

The command verifies that installed Chrome exactly matches consumer Stable for
that platform. Repeated polls are idempotent and report already_harvested.

For an explicitly non-canonical diagnostic:

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest capture \
  --platform linux \
  --no-release-check \
  --browser-mode headless \
  --samples 3 \
  --output captures/diagnostic
~~~

The resulting bundle is retained but marked non-ready.

## Chrome for Testing baseline

Chrome for Testing remains useful as a reproducible early-warning baseline,
but its testing field-trial configuration is not canonical consumer evidence:

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest cft-release --platform linux64

uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest cft-harvest \
  --platform linux64 \
  --samples 5 \
  --workspace .cache/fingerprint-harvester
~~~

Chrome-for-Testing bundles always report ready: false.

## Safari capture

Use the platform SafariDriver rather than substituting Chromium. A fresh
WebDriver session is created for every sample:

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest safari-capture \
  --platform macos \
  --samples 5 \
  --output captures/safari-macos
~~~

The `ios` platform uses an explicitly booted iOS Simulator and accepts its
device name, UDID, and runtime version as command-line options. Safari may be
HTTP/2-only at the collectors; absence of HTTP/3 is retained as evidence rather
than synthesized.

## Android Chrome capture

Android capture attaches Playwright as a CDP client to the installed
`com.android.chrome` package. Canonical captures clear a dedicated emulator
profile before every sample. ``--preserve-profile`` is available for safe
diagnostics on a personal device but is not compilation-ready when connection
state produces more than one variant.

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest android-capture \
  --serial emulator-5554 \
  --samples 5 \
  --output captures/chrome-android
~~~

The hosted workflow downloads Chrome and its exact-version Trichrome shared
library directly from Google Play, verifies their signatures, installs them on
an ARM64 Android emulator, and deletes the proprietary packages with the
ephemeral runner. Only sanitized fingerprint evidence is uploaded.

## Bundle contract

Each bundle is created atomically and is never overwritten:

~~~text
manifest.json
profile.json
capabilities.json
readiness.json
samples/
  000/
    raw.json
    normalized.json
~~~

- capabilities.json answers whether all observed native features are
  representable.
- readiness.json is the authoritative compilation gate. It also checks
  consumer distribution, sample count, variants, and headful provenance.
- profile.json clusters stable semantics and records randomized order as
  fixed, permuted, or unknown.

Raw samples are sanitized before storage. Public source IP, TCP/IP metadata,
TLS client random, and TLS session ID are removed. The full
chrome://version text and variation IDs remain for A/B diagnosis.

## Candidate generation

Only a bundle whose persisted readiness.json says ready: true can produce a
candidate:

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest candidate \
  captures/stable/151.0.7922.34/mac \
  --target chrome151 \
  --output profiles/chrome/chrome151.json

uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest render \
  profiles/chrome/chrome151.json \
  --output profiles/generated/chrome151.inc
~~~

The compiler is typed and fails on unknown options. The imported
profiles/chrome/chrome146.json must render exactly to the current chrome146
initializer:

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest render \
  profiles/chrome/chrome146.json \
  --check-patch patches/curl.patch
~~~

Compare full profiles or OS-independent transport behavior:

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest diff BEFORE AFTER

uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest diff --transport-only MAC WINDOWS
~~~

## Scheduled deployment

`fingerprint-harvest.yml` runs every six hours and on manual dispatch. It:

1. Captures headful consumer Chrome on Linux, Windows, macOS Intel, and macOS
   ARM.
2. Waits until the installed consumer Stable binaries reach the same major on
   all four platforms.
3. Requires matching OS-independent transport semantics.
4. Retains sanitized evidence and generates Linux, Windows, and macOS
   declarative profiles plus C initializers. The unsuffixed target remains the
   macOS-compatible default.
5. Builds every injected native target and replays each one through both
   collectors against its matching OS evidence.
6. Commits the verified profile set directly to the workflow's branch in the
   fork only after every replay matches.

The workflow needs `contents: write` permission. Google's announcement feed and
signed Stable downloads can advance at different times, so the workflow records
both and treats the installed consumer binary as capture truth. A candidate is
generated only when the actual major converges on every OS. Sanitized run
artifacts expire after seven days; evidence for a verified candidate is retained
in the profile commit.

The workflow intentionally does not tag or release.

`safari-fingerprint-harvest.yml` uses GitHub-hosted macOS and iOS Simulator
runners. `android-fingerprint-harvest.yml` uses the ARM64 `macos-15` runner
so Play-delivered ARM64 Chrome executes without native-code translation. The
Android workflow first attempts anonymous Play authentication and also accepts
an encrypted `GPLAY_AUTH_B64` token or `GPLAY_DISPENSER_URL` secret. It
never stores APKs in artifacts, commits, or releases.

## Browser and collector behavior

The launcher supports Linux, Windows, and macOS and records its minimal command
line. Headful is canonical. Linux requires a real display or Xvfb and never
silently falls back to headless. The harvester refuses to run Chrome as root
because disabling its sandbox changes launch provenance.

Default collectors are:

- https://tls.peet.ws/api/all for TLS and HTTP/2.
- https://fp.impersonate.pro/api/http3 for HTTP/3 and QUIC.

Production should use an owned TrackMe deployment for TLS/HTTP/2 and an owned
HTTP/3 packet observer. Both URLs are configurable.

## Native build and replay gate

The superbuild injects every `profiles/generated/*.inc` initializer into the
already-patched `lib/impersonate.c`. This keeps maintained patch files untouched
while making a reviewed declarative profile part of the native binary. Duplicate
targets and malformed initializers fail the patch step.

For a local, uncommitted candidate, point the build at another directory with
`-DCURL_IMPERSONATE_GENERATED_PROFILE_DIR=/absolute/path/to/initializers`.

Once a candidate is compiled, replay it through the same collectors:

~~~sh
uv run --project tools/fingerprint-harvester \
  curl-impersonate-harvest replay \
  profiles/evidence/chrome151/mac \
  --curl-binary build/deps/build/curl/src/curl-impersonate \
  --target chrome151 \
  --samples 3 \
  --output .cache/replay/chrome151
~~~

Replay exits successfully only when the complete normalized TLS, HTTP/2,
HTTP/3, QUIC, and header profile matches the retained Chrome bundle.

Chrome can vary TLS behavior between TCP and QUIC. Native profiles therefore
carry separate HTTP/3 signature algorithms and can suppress `status_request`
and `signed_certificate_timestamp` on QUIC without changing TCP TLS.

After native support covers every reported capability gap, the final release
gate is:

1. Review the retained four-platform evidence and generated profile.
2. Confirm the automated native build and semantic replay passed.
3. Merge and tag curl-impersonate.
4. Update downstream curl_cffi and other bindings.

diff, capabilities, and readiness exit with status 1 when their gate fails.
Operational errors exit with status 2.
