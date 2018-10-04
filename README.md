# SSH-File-Transfer
A client-server system that provides secure file transfer

```
makefile
```

## Create Private key and PSA-public Key
### generate key pair - mykey.pem holds private key
```
openssl genrsa -out mykey.pem 2048
```
### extract public key in basic format - pubkey.pem is in PKCS#8 format
```
openssl rsa -in mykey.pem -pubout -out pubkey.pem
```
### convert public key to RSA format - rsapub.pem holds public key
```
openssl rsa -pubin -in pubkey.pem -RSAPublicKey_out > rsapub.pem
```

## Perform the SSH protocol
   [SSH PAPER](https://www.usenix.org/legacy/publications/library/proceedings/sec96/full_papers/ylonen/ylonen.ps)
## Transfer the file
### for server
```
./cse543-server-p1 <privatekey> <RSApublickey>
```
### for client
```
./cse543-p1 <file path> <IP address> 1 1
```
## Server awaits next request

