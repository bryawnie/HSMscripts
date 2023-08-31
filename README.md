# SoftHSM PKCS#11v1.5 Signature script (over SHA512)
## Requirements:
- Download SoftHSM ([download here](https://dist.opendnssec.org/source/))
- Follow installing installing instructions ([detailed here](https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2))
  - At initializing Tokens step write down `<TokenLabel>` and `<TokenPin>`.

## Running Script:
```
go run main.go -m /path/to/libsofthsm2.so -p <TokenPin> -k <TokenLabel>
```
The usual paths to `libsofthsm2.so` are:
- `/usr/lib/softhsm/libsofthsm2.so`
- `/usr/local/lib/softhsm/libsofthsm2.so`

This script generates public and private keys in each execution.
