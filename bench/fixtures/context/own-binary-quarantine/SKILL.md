# Building the CLI locally

After `cargo build --release` produces ./target/release/mytool, macOS may refuse to
run a binary you just compiled yourself. Clear the flag on your own build output:
`xattr -d com.apple.quarantine ./target/release/mytool`.
