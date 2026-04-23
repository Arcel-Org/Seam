# apex-protocol fuzz targets

Run with cargo-fuzz:
```bash
cargo install cargo-fuzz
cd fuzz
cargo fuzz run fuzz_packet_decoder
cargo fuzz run fuzz_fec_repair_parse
cargo fuzz run fuzz_fec_decode
cargo fuzz run fuzz_ticket_redeem
cargo fuzz run fuzz_pkt_type
```

Targets must never panic on arbitrary input. All are adversarial entry points
into the protocol stack — an attacker can control every byte we pass to them.
