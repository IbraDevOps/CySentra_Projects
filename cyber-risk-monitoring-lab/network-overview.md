# Network Overview — Abr LTD (As-Is)

## Internet Connectivity
AB LTD receives internet connectivity from a local Internet Service Provider (ISP). The ISP cable terminates into a single router installed within the office premises.

## Router & Wireless Network
The router performs the following functions:
- Network gateway (NAT)
- Basic firewalling using default ISP configuration
- Wireless access point (Wi-Fi)

There is a single flat Wi-Fi network used across the organization. No VLANs, guest networks, or network access controls are implemented.

## Connected Devices
All of the following devices connect to the same Wi-Fi network:
- Employee laptops and desktop PCs
- Employee smartphones (personal devices used for work)
- Internal office phones
- Network printers
- CCTV cameras

## Security Implications
The Wi-Fi network represents the primary trust boundary. Compromise of any single connected device may allow an attacker to access or observe other devices on the network.
