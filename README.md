### PH0B05

[AWS Article here]: https://aws.amazon.com/blogs/security/how-to-use-aws-kms-rsa-keys-for-offline-encryption/

Example of building a hybrid offline encryption system based on [AWS Article here].

The idea is to create a hybrid system that uses AES to encrypt data locally and using the RSA KMS public key, which is downloaded locally, to further encrypt the generated key used in the AES encryption.

This has the following benefits:

* In the event that the KMS API is unavailable, the data can be encrypted locally using the available KMS public key

* It allows larger files to be encrypted since RSA has a 190 bytes limit

* It saves on costs as its not calling KMS API for encrypt operations per file


The encryption workflow based on the article becomes:

* Create RSA keypair in KMS
* Create random 32 byte key locally
* Use random 32 byte key above to encrypt file
* Get the public RSA key
* Use public key from RSA KMS keypair to encrypt the random key
* Save as artifacts the encrypted random key and the encrypted file object


The decryption process becomes:

* For decryption we decrypt the encrypted random key using KMS
* Use the decrypted key to decrypt the file object


Note that this has the ability to encrypt larger file objects since RSA has an upper limit of 190 bytes.

### To run

```
go mod init

go mod tidy

make build
```

Create a KMS RSA assymmetric keypair with an alias.

Add your AWS details and key alias to the .env file

Source the .env file in the same terminal
```
cp .env.example .env

source .env
```

We need to download the Public Key from KMS using the following command:
```
./build/phobos download-cert --path ./certs/public_key.der
```

The public key will be returned as a DER-encoded X.509 public key, also known as SubjectPublicKeyInfo (SPKI)

We pass the saved public key during encryption to encrypt the random key:
```
./build/phobos encrypt \
  --cert-der ./certs/public_key.der \
  --source <FILE> \
  --target <FILE>
```

To decrypt the encrypted file and key:
```
./build/phobos decrypt \
  --source <ENCRYPTED FILE> \
  --target <DECRYPTED FILE>
```



### TODOS

* Add more tests
* Add GH workflow to build and deploy 
