### PH0B05

[AWS Article here]: https://aws.amazon.com/blogs/security/how-to-use-aws-kms-rsa-keys-for-offline-encryption/

Example of building a hybrid offline encryption system based on [AWS Article here].

The idea is to use a RSA KMS key to encrypt and decrypt locally created AES keys. 

The encryption workflow based on the article becomes:

* Create RSA keypair in KMS
* Create random 32 byte key locally
* Use random 32 byte key above to encrypt file
* Use public key from RSA KMS keypair to encrypt the random key
* Save as artifacts the encrypted random key and the encrypted file object

The difference with the article is we don't download the public key but instead call out to KMS API to encrypt the locally generated key...

The decryption process becomes:

* For decryption we decrypt the encrypted random key using KMS
* Use the decrypted key to decrypt the file object


Note that this has the ability to encrypt larger file objects since RSA has an upper limit of 190 bytes

### To run

```
go mod init

go mod tidy

make build
```

The CLI takes the following commands:

```
encrypt --source <FILE> --target <FILE>
```

```
decrypt --source <ENCRYPTED FILE> --target <DECRYPTED FILE>
```

Create a KMS RSA assymmetric keypair with an alias.

Add your AWS details and key alias to the .env file

Source the .env file in the same terminal
```
cp .env.example .env

source .env
```