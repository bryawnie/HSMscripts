# SoftHSM Signature script
## Requirements:
- Download SoftHSM ([download here](https://dist.opendnssec.org/source/))
- Follow installing instructions ([detailed here](https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2))
  - At initializing Tokens step write down `<TokenPin>`.
- Write down `<SlotId>`. You can list the available slots with:
  ```
  softhsm2-util --show-slots
  ```
- Generate a new key pair. Some examples below:
  - __RSA PKCS#11 v1.5__: `pkcs11-tool --module /path/to/libsofthsm2.so --slot <SlotId> --login --pin <TokenPin> --keypairgen --key-type rsa:2048 --label <KeyLabel>`
  - __CKM ECDSA__: `pkcs11-tool --module /path/to/libsofthsm2.so --slot <SlotId> --login --pin <TokenPin> --keypairgen --key-type EC:prime256v1 --label <KeyLabel>`
  - *__Note__: Keypairs are overwritten if generated twice*.

> The usual paths to `libsofthsm2.so` are:
> - `/usr/lib/softhsm/libsofthsm2.so`
> - `/usr/local/lib/softhsm/libsofthsm2.so`

> __Show Supported Mechanisms__
> ```
> pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -M
> ```

## Running Script:
```
go run main.go -m /path/to/libsofthsm2.so -p <TokenPin> -k <KeyLabel>
```

This script uses the previously generated keypair. Signs a message and then verifies the signature.
