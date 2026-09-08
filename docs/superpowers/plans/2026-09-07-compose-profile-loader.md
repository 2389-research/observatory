# Compose profile loader implementation plan

**Goal:** `docker compose up -d` starts Observatory on a Linux Docker/KVM host without running an installer or writing host configuration files.

**Approved design:** A short-lived Compose service loads the bundled AppArmor profile into the shared kernel. The appliance depends on its successful completion and keeps its current confinement. Doctor Biz approved the loader's policy-management authority. No host packages, systemd units, sudoers entries, or `/etc/apparmor.d` files are installed.

**Architecture:** Ship the parser and profile in the appliance image; the setup service invokes the parser directly. Give the setup service only the measured policy-loading capability and securityfs access, no Docker socket or host root mount. Compose reloads policy before each startup, including a startup after the kernel lost the profile. Developer wrappers use this same Compose service rather than a second installer.

**Global constraints:** Retain runtime seccomp, AppArmor, capabilities, devices, uid split, persistent volume names, and fail-closed startup. Do not run or recreate the deleted host installer. Existing untracked P4 plan belongs to prior work. Host reboot is not authorized; simulate profile loss only while Observatory is down.

## Work and evidence

- [x] Add failing deployment tests for the loader boundary, image contents, dependency and absence of host install requirements.
- [x] Implement the Compose service, bundled parser/profile, and wrapper integration; delete the host installer and update obsolete tests to the new contract.
- [x] Run a real Linux Compose test for absent policy, repeat startup, profile loss, loader failure, and VM lifecycle under the confined profile. Preserve logs outside throwaway containers.
- [x] Update operator docs, gotchas and this session's PLAN.md entry.
- [x] Run `scripts/check`, docs validation, and independent final review; commit the reviewed change.

## Status

Complete. PR #2 merged at `a6a13949e60ef9daf38e07d745043fe145b8a161`; image workflow `34181381348` published that revision to GHCR. Compactions: 0.

Evidence: six portable tests failed before implementation, then deployment tests passed. Real Compose test initially refused the old published image because it lacks the parser. With the built image it passed all startup/failure/reload/VM checks (15.35s); the first test revision read POST's VM at the wrong JSON level, corrected against the handler and actual response. M0 gate passed through the loader under confinement (11.19s). `scripts/check` passed all ten gates; docs validation passed 47/47. Logs: `/tmp/vmobs-compose-{red,live,gate,check,docs}.log` on the development machine; M0 transcript preserved at `/tmp/vmobs-compose-m0-evidence.txt` on aibox03. No reboot performed.

Review found no blockers. The loader has shared-kernel policy authority, not authority restricted by the kernel to one profile name; the shipped command loads only the bundled profile.

Final registry verification: a fresh checkout at `~/observatory-compose-install` on aibox03 pulled `ghcr.io/2389-research/observatory:latest`. `TestComposeLive` passed against that published image (15.28s), including the real VM lifecycle and policy-loss recovery. Log: `/tmp/vmobs-compose-published-live.log` on the development machine. No installer or host configuration file was used.
