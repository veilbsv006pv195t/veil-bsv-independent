# Demo compatibility

Veil has a static browser demo and a separate developer replay workflow. The
browser demo is the portable option: the server only delivers files, while the
visitor's browser creates and verifies the proof.

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

## Static hosting computer

Any computer capable of serving static files can host `dist-ui/`. Examples
include an inexpensive Linux VPS, an ARM64 single-board computer, a Windows IIS
host, Nginx, Caddy, Apache, or a static hosting service. The host does not create
proofs and needs no database, wallet, GPU, or persistent application process.

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

## Presentation recommendation

For the least risky bounty demonstration, host `dist-ui/` on HTTPS and present
it from a current Chromium-based browser on a laptop with 8 GB or more RAM. Keep
the command-line replay available on a separate development machine to show the
Bitcoin Script VM acceptance and rejection tests.
