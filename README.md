#  Scripts for HSM
This basic script allows you to:
- Generate keypairs in HSM.
- Sign some content (a message) with the keys in HSM.
- Verify a signature issued by HSM, given the corresponding message.
- Generate random bytes (64 bytes to be precise).
## Using SoftHSM
Instead of usinga real HSM, you can download and install SoftHSM ([download](https://dist.opendnssec.org/source/) | [installation guide](https://wiki.opendnssec.org/display/SoftHSMDOCS/SoftHSM+Documentation+v2)). When installing softHSM, I recommend to write down `<TokenPin>` and `<TokenLabel>`. Also, you will need to know the path location of `libsofthsm2.so`:
> The most common paths to `libsofthsm2.so` are:
> - `/usr/lib/softhsm/libsofthsm2.so`
> - `/usr/local/lib/softhsm/libsofthsm2.so`

### Random Bytes Generation
With previous steps done, you can already generate random bytes with:
```
./hsm-app random -l /path/to/libsofthsm2.so -p <TokenPin>
```
In order to sign and verify, it is needed to generate a keypair. In this case we will use RSA keys with length 4096.

### Key Generation
In order to generate keys, you will need to assign them a `<KeyLabel>` (which allow us to retrieve them later). Just make the following execution:
```
./hsm-app keygen -l /path/to/libsofthsm2.so -p <TokenPin> -k <KeyLabel>
```

### Sign
Having a keypair with keylabel `<KeyLabel>`, you can sign a message with:
```
./hsm-app sign -m "Your Message" -l /path/to/libsofthsm2.so -p <TokenPin> -k <KeyLabel>
```

### Verify Signature
You can also verify a signature over some message under a keypair with keylabel `<KeyLabel>` with:
```
./hsm-app verify -m "Your Message" -s <Signature> -l /path/to/libsofthsm2.so -p <TokenPin> -k <KeyLabel>
```

### Extract Public Key
You can also verify a signature over some message under a keypair with keylabel `<KeyLabel>` with:
```
./hsm-app extract-key -l /path/to/libsofthsm2.so -p <TokenPin> -k <KeyLabel>
```

### [Alternative] Key Generation
You can also generate keys by console following these steps:
- Write down the corresponding `<SlotId>`. You can list the available slots with:
  ```
  softhsm2-util --show-slots
  ```
- Generate a new key pair.
  - __RSA PKCS#11 v1.5__: `pkcs11-tool --module /path/to/libsofthsm2.so --slot <SlotId> --login --pin <TokenPin> --keypairgen --key-type rsa:2048 --label <KeyLabel>`
  - __CKM ECDSA__: `pkcs11-tool --module /path/to/libsofthsm2.so --slot <SlotId> --login --pin <TokenPin> --keypairgen --key-type EC:prime256v1 --label <KeyLabel>`
  - *__Note__: Keypairs are overwritten if generated twice with this method*.


### Useful SoftHSM Tools

> __Show Supported Mechanisms__
> ```
> pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -M
> ```

> __Show Current Keys__
> ```
> pkcs11-tool --module /usr/local/lib/softhsm/libsofthsm2.so -O
> ```

## Using Real HSM
In our case we use __Luna HSM Client__ to communicate with the real HSM through `libCryptoki2_64.so`. Docker files are in charge to load this library into a container environment. 

__Docker application__ works as *one shot* execution, specifying arguments such as message, signature, etc in `.env` file. For example:
```
SUBCOMMAND=your-subcommand
TOKEN_PIN=123456
KEY_LABEL=MyKeyLabel
MODULE_LOCATION=path/to/libCryptoki2_64.so
MESSAGE="My Message"
SIGNATURE="My Signature"
```

