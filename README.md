# EAP-5G LUA Dissector

A simple yet useful Wireshark Lua dissector for the EAP-5G protocol (Ref. 3GPP TS 24.502 V17.7.0).

## Overview

EAP-5G, defined in [3GPP TS 24.502](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3371), is an EAP-Expanded (Vendor-ID 10415, Vendor-Type 3) protocol used by the UE and N3IWF/TNGF to exchange control information in the 5G Non-3GPP Access. Wireshark ships no native dissector for it, so EAP-5G packets normally show up only as generic EAP-Expanded data. This dissector decodes the EAP-5G header and AN-Parameters, delegating the embedded NAS-PDU to Wireshark's built-in dissector for full 5G NAS decoding.

## Features

- Detects EAP-5G packets (EAP-Expanded, Vendor-ID 3GPP, Vendor-Type 3).
- Decodes all EAP-5G message types:
  - 5G-Start;
  - 5G-NAS (Request and Response);
  - 5G-Notification (Request and Response);
  - 5G-Stop.
- Decodes the following AN-Parameters:
  - Globally Unique AMF ID (GUAMI);
  - Selected PLMN ID;
  - Requested NSSAI (SST/SD);
  - Establishment Cause for Non-3GPP Access;
  - Selected NID;
  - UE Identity;
  - TNGF IPv4/IPv6 Contact Info.
- Invokes Wireshark's `nas-5gs` dissector to decode the encapsulated 5G NAS-PDU.

## Installation

1. Copy `eap-5g.lua` into your Wireshark personal (or global) Lua plugins folder:

   | OS | Path |
   |---|---|
   | Linux (per-user) | `~/.local/lib/wireshark/plugins/` |
   | Linux (system-wide, Ubuntu/Debian) | `/usr/lib/x86_64-linux-gnu/wireshark/plugins/` |
   | macOS | `~/.config/wireshark/plugins/` |
   | Windows | `%APPDATA%\Wireshark\plugins\` |

   (You can check the exact plugin folder for your system under *Help > About Wireshark > Folders* in the Wireshark UI.)

2. Restart Wireshark, or reload Lua plugins via *Analyze > Reload Lua Plugins* (Ctrl+Shift+L).

## Usage

Just open a capture containing EAP-5G traffic (e.g., from a 5G non-3GPP access registration procedure): the dissector runs automatically as a postdissector.

## License

Distributed under the MIT License — see [LICENSE](LICENSE).

## Contributing

Bug reports and pull requests are welcome.
