# neEDRe
A self-made EDR program that runs on Linux. Implemented with [Aya](https://aya-rs.dev/).

## Detectable events
- Detects execution from suspicious path prefixes (default: `/tmp`).

## Other features
- Records timestamped detection entries to `/var/log/needre/needre_detect.log`.
- Sends all audit logs to journald (`info` level).
- Runs as a systemd service.

## Requirements
- Linux 5.8 or later
- Requires root privileges to load the eBPF program and to write to `/var/log/needre`.

## Logs
- Logs needre's activity to journald at `info` level.
```sh
  journalctl -u needre -f
```
- Detection log: records security events. (Default path: `/var/log/needre/needre_detect.log`)

## License
With the exception of eBPF code, needre is distributed under the terms
of either the [MIT license] or the [Apache License] (version 2.0), at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.

### eBPF

All eBPF code is distributed under either the terms of the
[GNU General Public License, Version 2] or the [MIT license], at your
option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, as defined in the GPL-2 license, shall be
dual licensed as above, without any additional terms or conditions.

[Apache license]: LICENSE-APACHE
[MIT license]: LICENSE-MIT
[GNU General Public License, Version 2]: LICENSE-GPL2
