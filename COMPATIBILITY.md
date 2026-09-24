# Replay compatibility

The complete bounty replay is a local command-line workflow. It starts no
public service and needs no wallet or blockchain connection. Veil also has a
supplementary browser demo for developers, but that UI is not part of the
bounty acceptance path.

## Browser demo

| Computer | Status | Recommended browser |
| --- | --- | --- |
| Apple Silicon Mac | Tested | Current Brave, Chrome, Edge, Firefox, or Safari |
| Intel Mac | Expected to work | Current Chrome, Edge, Firefox, Brave, or Safari |
| Windows 10 or 11 PC | Expected to work | Current Chrome, Edge, Firefox, or Brave |
| 64-bit Linux desktop | Expected to work | Current Chrome, Chromium, Firefox, or Brave |
| Chromebook | Expected to work | Current Chrome |
| iPad, iPhone, or Android device | UI-compatible, but not recommended for a live proof demonstration | Current Safari or Chrome |

The browser must support WebAssembly, JavaScript `BigInt`, Web Crypto, and
modern ES modules. For a reliable presentation, use a laptop or desktop with:

- a 64-bit browser;
- at least 4 GB RAM, with 8 GB recommended;
- roughly 20 MB free browser cache;
- JavaScript and WebAssembly enabled; and
- a local or HTTPS web origin. Web Crypto may be unavailable on an ordinary
  remote HTTP origin.

The first proof loads an approximately 11 MB proving key. Proofs took under one
second on the tested machine, but slower computers may need several seconds.

### Tested configuration

- Apple Silicon (`arm64`)
- macOS 26.5.1
- Brave 152.1.94.121
- Node.js 25.1.0 for the development workflow

Other rows describe expected compatibility based on the browser APIs used; they
have not been independently tested as part of this release.

## Full protocol replay

Rebuilding the circuit and contract requires:

- Node.js 20 or newer and npm;
- a 64-bit macOS, Linux, or Windows development computer;
- at least 4 GB RAM, with 8 GB recommended;
- approximately 1 GB free disk space for dependencies and generated setup
  files; and
- network access for the initial `npm ci` and sCrypt compiler download.

The full build was tested only on Apple Silicon macOS. The pinned sCrypt tooling
contains compiler selection for macOS, Linux, and Windows, but a clean replay
should be performed on the exact target operating system before a public demo.

## Review recommendation

For a non-developer review on macOS, download and extract the release archive,
then double-click `RUN_REPLAY.command`. The Terminal window reports a single
pass or fail result after the full protocol and Bitcoin Script tests complete.
The optional browser demo is not needed.
