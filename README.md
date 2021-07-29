# SBE Wiresharker

### Blurb:
This project allows the generating of wireshark dissectors in Lua.

### Features:
- High test coverage
- Supports multiple SBE schemas in a single dissector
- Supports SBE schemas enveloped within other SBE schemas
- Supports use of frames like Simple Open Framing Header (as long as they are fixed length)
- Dissectors will attach themselves to whatever port ranges you provide
- Complies with SBE 1 specification
- Will decode messages sent with a newer version of an SBE schema
- Handles fragmentation of message stream across multiple TCP packets

### TODO:
- Add a command line API instead of relying on programmatic invocation
- Split out tests into more manageable suits
- Add support for decoding messages sent with an older version of an SBE schema
- Find a neater way of representing tests (lots of XPath complexity exposed in tests)

### Notes:
- Only programmatic invocation is currently supported
- When providing multiple SBE schemas, they must not overlap on schema IDs
- The tests require `tshark` (ships with `wireshark`) to run