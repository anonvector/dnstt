# DNSTT (SlipNet Fork)

A hardened fork of [dnstt](https://www.bamsoftware.com/software/dnstt/) — a userspace DNS tunnel with DoH, DoT, and UDP support.

This fork is maintained by [SlipNet](https://github.com/anonvector/SlipNet) and includes significant modifications for production use in censorship-resistant networking.

## Changes from upstream

Based on [tladesignz/dnstt](https://github.com/tladesignz/dnstt) (itself a fork of [David Fifield's original](https://www.bamsoftware.com/software/dnstt/)).

Key modifications in this fork:

- **Server hardening** — session/stream limits, client eviction, removed PT dependency
- **Extracted server core into a reusable library** with pluggable hooks
- **TXT-only mode** — removed A-record/AAAA anti-filter mode for simplicity
- **Configurable query rate and retry settings** for mobile optimization
- **Battery optimization** — reduced DoH senders from 32 to 12
- **Graceful shutdown** — suppressed closed-connection errors during teardown
- **Fixed sendLoop** retrying forever on closed transport

## License

This fork is licensed under the **GNU Affero General Public License v3.0 (AGPL-3.0)**.

The original dnstt code by David Fifield is public domain (CC0). The upstream fork by tladesignz is also CC0. This fork relicenses the combined work under AGPL-3.0 to ensure that modifications to this code — including use over a network — remain open source.

See [COPYING](COPYING) for the full license text.

## Overview

dnstt is a DNS tunnel with these features:
 * Works over DNS over HTTPS (DoH) and DNS over TLS (DoT) as well as
   plaintext UDP DNS.
 * Embeds a sequencing and session protocol (KCP/smux), which means that
   the client does not have to wait for a response before sending more
   data, and any lost packets are automatically retransmitted.
 * Encrypts the contents of the tunnel and authenticates the server by
   public key.

dnstt is an application-layer tunnel that runs in userspace. It doesn't
provide a TUN/TAP interface; it only hooks up a local TCP port with a
remote TCP port (like netcat or `ssh -L`) by way of a DNS resolver.

```
.------.  |            .---------.             .------.
|tunnel|  |            | public  |             |tunnel|
|client|<---DoH/DoT--->|recursive|<--UDP DNS-->|server|
'------'  |c           |resolver |             '------'
   |      |e           '---------'                |
.------.  |n                                   .------.
|local |  |s                                   |remote|
| app  |  |o                                   | app  |
'------'  |r                                   '------'
```

## Usage

Refer to the original [dnstt documentation](https://www.bamsoftware.com/software/dnstt/) for general setup instructions (DNS zone, server/client configuration, proxy setup).

## Encryption

The tunnel uses Noise_NK_25519_ChaChaPoly_BLAKE2s for end-to-end encryption between client and server, independent of the DoH/DoT transport layer.

```
application data
smux
Noise
KCP
DNS messages
DoH / DoT / UDP DNS
```
