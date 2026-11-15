# PokeAlliance: HWID Collection & Fingerprinting

`PokeAlliance_dx.exe` is an x86-64 client, Themida-packed, 103,645,184 bytes once unpacked. It is an OTClient fork with the Lua layer replaced by native C++. At login it reads the firmware table, hashes it into a 40-character token, and sends that token in a 388-byte frame over the plaintext game channel.

## 1. The formula

```
HWID = SHA1( "u:" + uuid + ";"  [+ "s:" + serial + ";"] [+ "b:" + board + ";"] [+ "d:" + disk + ";"] )
     = 40 lowercase hex characters
```

Every term is a label, a value, and a `;`. Labels go out in a fixed order (`u:`, `s:`, `b:`, `d:`), and any of them can be missing, so the pre-image is whatever survives the filter in §3.

One branch replaces the string instead of adding to it: if every term is rejected, the builder writes `g:` + `MachineGuid`, with no trailing `;`.

The SHA-1 is in the image, not in bcrypt: `0x01577420` holds the five constants. The seven `BCryptFinishHash` calls at login are TLS, all of them between ClientHello and Finished.

## 2. The terms

| Label | Source | Format |
|---|---|---|
| `u:` | SMBIOS type-1 UUID, 16 bytes at record+8 | 32 uppercase hex, raw table order, no dashes, no endianness fixup |
| `s:` | type-1 serial, string index at record+7 | as stored |
| `b:` | type-2 (baseboard) serial | as stored |
| `d:` | first physical disk serial | as returned |
| `g:` | `HKLM\SOFTWARE\Microsoft\Cryptography` → `MachineGuid` | as stored, fallback only |

On a machine with real serials the pre-image is longer; on one with placeholders it collapses to the UUID alone.

## 3. Why the serials get dropped

`0x008AAFF0` runs two passes over each candidate string.

Statistical: length, character set, distinct symbols, most-frequent symbol, entropy, an arithmetic run of eight or more base-36 symbols, and an eight-digit `YYYYMMDD` window.

Keyword: fifteen words at `0x02020020`, matched with `std::search`. `serial` is first; the rest are the usual `changeme` / `notavailable` / `default` / `unknown` family.

So the board serial here, the literal string `None`, dies on length, while the type-1 serial `VMware-d6 18 4f …` passes every statistical rule and hits no keyword. It should be in the pre-image.

Which is where the trap is. The Frida script rewrites `VMware-` to `Serial-` for anti-VM cover, and `Serial-` matches keyword 0. Every early capture in this lab lost the system serial that way, and the token looked UUID-only. Four runs, same guest, same UUID, one variable:

| Type-1 serial | Pre-image | Token |
|---|---|---|
| `VMware-d6 18 4f …` (unmodified) | `u:…;s:VMware-d6 18 4f …;` | `4ba13b2df814e5bdec00948b1ea3d0ec4ae903e7` |
| `Vendor-d6 18 4f …` | `u:…;s:Vendor-d6 18 4f …;` | `d07d16ec486910e4d9c7b3420a0d18f28d14238c` |
| `Serial-d6 18 4f …` | `u:…;` | `bf968067a9a8e319fd21d9bd6fe6d35ec03aa40a` |
| `K9P34…`, 54 alphanumerics | `u:…;s:K9P34…;` | `040702ac8ab13a8e2f9ad30ef14265fd8420ff0a` |

Row one is what an untouched guest sends. Row three is what this lab was sending for a day. All four are one VM, bare metal usually adds `s:` and `b:`, and `d:` when the disk reports a serial, so its pre-image is longer and its token cannot be derived from these.

## 4. The packet

388 bytes, plaintext, 16-byte header and 372 bytes of payload. No opcode; the session id doubles as the demultiplexer.

| Offset | Field |
|---|---|
| `0x00` | `u16` total length, 386 |
| `0x02` | `u32` session id |
| `0x06` | `u32` 1 |
| `0x0A` | `u32` 1 |
| `0x0E` | `u16` payload length, 372 |
| `0x10` | `u32`, per run |
| `0x14` | `u16` 10, `u16` 20, `u16` 854 |
| `0x1A` | `u16` 28 + 28 base64 chars |
| `0x38` | `u16` 2 + `RK` |
| `0x3C` | `u16` 20 + CPU name |
| `0x52` | `u16` 40 + HWID |
| `0x7C` | 264 bytes, per run |

Two fields deserve a look. `0x1A` is `InstallId` from `HKLM\Software\PokeAlliance`: written on first run, replayed since, not derived from the HWID. `0x7C` is 264 random bytes, entropy 7.2, not one byte shared between two captures, so a nonce or per-session ciphertext rather than a fingerprint.

The CPU name is cut to 20 characters at `0x3C`, which is why it reads `12th Gen Intel(R) Co`.

## 5. Frida

The obstacle is the packer. Themida intercepts `VirtualProtect` in-process, so the page never becomes writable and `Interceptor.attach` on `.text` kills the process. That is why nothing here is measured by hooking the builder at `0x008AC430`, the numbers come from imports.

The hook set has to stay small, too. Adding five more `kernel32` hooks stopped the client reaching the network altogether: no `WSASend`, no frame, no token.

```js
const gsft = Module.getExportByName('kernel32.dll', 'GetSystemFirmwareTable');
Interceptor.attach(gsft, {
  onEnter(args) { this.sig = args[0]; this.buf = args[2]; },
  onLeave(ret) {
    const n = ret.toInt32();
    if (this.buf.isNull() || n <= 0) return;
    console.log('SMBIOS', n, 'B, sig', this.sig);
    console.log(hexdump(this.buf, { length: Math.min(n, 256) }));
  }
});
```

That gets you the table the client parses. For the token itself, `Interceptor.attach` on `ws2_32!WSASend` and filter for a buffer of 300 to 480 bytes. The HWID is 40 ASCII hex characters at `+0x52`, with the CPU name in front of it.

The client reads the table twice per session. The second read is the one the builder uses, about 10 ms before the upload.

There is a tamper detector and it never fires: a guard page plus a 66-byte VEH at `0x898520` watch a `0x1000` range, set a global flag on any access, and continue silently. It is armed at login. After a full session the flag is still 0.

## 6. What changes the HWID

| Change | Effect |
|---|---|
| SMBIOS type-1 UUID | rotates; the only term on a typical machine |
| System or board serial, to a plausible value | rotates, adds `s:` or `b:` |
| Same, to a short or repetitive value | no effect, rejected by the filter |
| Disk serial | rotates, adds `d:` |
| `MachineGuid` (reinstall, sysprep) | no effect unless nothing else survives |
| CPU | no effect on the token; the CPU string is a packet field |
| Username, RAM, volume serial, computer name, OS build | no effect, not collected |

A CPU swap keeps the HWID; a one-line SMBIOS edit rotates it. And since the identifier is unsalted and unkeyed, anyone who can read the firmware table can compute the token, and anyone who can set that table can forge it.

## Unresolved (for now).

- The process holds an unpatched 10,248-byte copy of the SMBIOS table alongside the patched one, 483 ms later and 607 MB higher in the heap, even though it never runs unhooked. Something reads the table without going through `kernel32`, either a direct `NtQuerySystemInformation(SystemFirmwareTableInformation)` call or the `mssmbios` registry value. It does not reach the hash, the four tokens above only work if the builder reads the patched table.
- The `d:` term has never produced a token here. The reader is `0x008ABFA0`, this guest has no disk serial.
- `0x18` is 854 in every capture. Build number is the obvious guess and nothing confirms it.

## Appendix: addresses

November 2026 build, RVAs against the unpacked image. File offset equals RVA, the file on disk is packed, so disk offsets do not match. The base moves per boot.

| Role | RVA |
|---|---|
| HWID builder | `0x008AC430` |
| SMBIOS parser (UUID + serials) | `0x008AB990` |
| Serial plausibility filter | `0x008AAFF0` |
| Keyword blacklist | `0x02020020` |
| `MachineGuid` reader (the `g:` fallback) | `0x008AAEA0` |
| `g:` term site | `0x008ACE13` |
| Disk serial reader | `0x008ABFA0` |
| Digest wrapper | `0x00914510` |
| SHA-1 descriptor | `0x01535C00` → `0x01DF44B0` |
| SHA-1 initialiser (constants) | `0x01577420` |
| `InstallId` reader | `0x008AC2D0` |
| `"u:"` literal / `";"` / `%02X` format | `0x02040908` / `0x0200DD10` / `0x02040A2C` |
| Guard-page VEH | `0x00898520` |
| Anti-VM hypervisor-brand check | `0x008988C0` |
