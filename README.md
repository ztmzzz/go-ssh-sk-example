# Go SSH FIDO/U2F Key Example

This repository contains a simple example that implements FIDO/U2F keys in SSH using the Go language.

The example shows how to use an `ed25519-sk` key from the client side without changing the original SSH library code. To
use `ecdsa-sk` keys, you can make similar small tweaks.

The needed changes are minimal, and the key challenge is not to modify the existing SSH library.

I have successfully tested this on my YubiKey.