# MHXX CTRPF Mod Menu (`mhxx_ctrpf.nro`)

An on-device cheat menu for **Monster Hunter XX (Switch)** — `0100C3800049C000`,
build `9D4C86E6EF74504A` — modelled on 3DS CTRPF: a flat list of toggles, a
numeric keypad, pad **and** touch input, and a CTRPF-style boot log.

## Why a `.nro` and not a sysmodule

A homebrew `.nro` has **no debug capability**, so it cannot call
`svcDebugActiveProcess`. Atmosphère's `dmnt` does, and `dmnt:cht` exposes the
attached process to any title. So this menu uses **`dmnt:cht` only**:

| op | command |
|---|---|
| ForceOpen / ForceClose | 65003 / 65006 |
| metadata (pid, main base, build id) | 65002 |
| read / write cheat memory | 65102 / 65103 |
| freeze / unfreeze an address | 65303 / 65304 |

That means it never competes for a debug session with Nxus, EdiZon or the
Atmosphère cheat engine, and it needs no NPDM patching.

## Safety model

1. **Build-id gate** — `dmnt` metadata must report `9D4C86E6EF74504A`, *and* the
   first patch site must hold either its original or its patched word before
   anything is written. (The NSO header is not mapped in memory, so the code
   signature is the honest check.)
2. **Original-word check per site** — every site is compared to its expected
   original instruction first; a mismatch aborts that cheat and writes nothing.
3. **Read-back verification** — every write is read back and compared.
4. **Revert all (Y)** — restores the original words for every site the menu
   recognises as patched.
5. **Freeze is dmnt-native** — values are frozen by `dmnt` itself, so they stay
   frozen even with the menu closed.

## Contents

- **15 code patches** (`P1`..`P15`): money/points max & freeze, shop ignores
  price, infinite health/stamina, sharpness, hunter-art / brave / alchemy
  gauges, pouch items, bomb-&-trap placement. Each is a **one-word AArch32
  instruction swap** — no trampoline, no extra page, no allocation.
- **6 pointer-chain values** (`F1`..`F6`): zenny, Bherna points, attack,
  defence, FPS cap, game speed. `A` opens the keypad, `X` freezes.
- **Tools**: re-verify build id, revert all, exit.

## Controls

| input | action |
|---|---|
| D-Pad / left stick | move |
| A / touch tap on a row | toggle patch, open keypad for a value |
| X | freeze / unfreeze the selected value |
| Y | revert all patches |
| B / `-` | exit (hands the process back to `dmnt`) |

## Install

```
SD:/switch/mhxxctrpf/mhxxctrpf.nro
SD:/switch/mhxxctrpf/README.txt
```

Open the Homebrew Menu, run `mhxxctrpf`, and the boot log reports each stage
(`dmnt:cht`, application, build id, module, hooks) before the menu appears.

## Verified against the real binary

All 30 patch-site words were checked against the extracted `main.bin`
(`0x51E02C = 0xB1A02001`, `0x51E02CC`… etc.) — **30/30 match, 0 mismatches** —
and the pointer chains were resolved against a live running game, where
`F5` (`system+0x484C`) read back `0x42700000` (= 60.0f), exactly the documented
default.

Note: if an Atmosphère cheat file (`atmosphere/contents/0100C3800049C000/cheats/
9d4c86e6ef74504a.txt`) already enables a cheat, the corresponding site shows as
already-patched in memory and the menu reports it as `[ON]`. Turning it off in
the menu may be re-applied by `dmnt` — disable the cheat file entry instead.
