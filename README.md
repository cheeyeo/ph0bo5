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

### To Run

Assuming we have a single file of `test.txt`, the commands below will generated an encrypted file of `test.txt.enc` and a private AES key `test.txt.key` used to encrypt the file. This key is encrypted using the public key of the KMS RSA key.


We need to download the Public Key from KMS using the following command:
```
./build/phobos download-cert \ 
  --alias <KMS KEY ALIAS> \
  --path ./certs/public_key.der
```

The public key will be returned as a DER-encoded X.509 public key, also known as SubjectPublicKeyInfo (SPKI). The application will parse and return the appropriate RSA public key from it.

We pass the saved public key from above ^ during encryption to encrypt `test.txt.key`:
```
./build/phobos encrypt \
  --cert-der ./certs/public_key.der \
  --source test.txt \
  --target test.txt.enc
```

To decrypt the encrypted file and key:
```
./build/phobos decrypt \
  --source test.txt.enc \
  --target test.txt \
  --alias <KMS KEY ALIAS>
```

To re-encrypt the key material, we can run the following:
```
./build/phobos reencrypt \
  --sourcek <KMS SOURCE KEY ALIAS> \
  --destk <NEW KEY ALIAS> \
  --source test.txt.enc
```

Re-encrypt is only used during key rotation. It uses the public key of a new RSA KMS keypair to re-encrypt the encrypted key ( test.txt.enc ). There is no need to re-encrypt the `test.txt` or source files again as only the encrypted key has changed. Using the right key alias during decrypt will use the right private key to decrypt the key.


### TODOS

* Add more tests
* Add GH workflow to build and deploy 
