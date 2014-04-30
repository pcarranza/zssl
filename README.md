# ZSSL
## Zoocial ssl like terminal implementation

This project covers two big goals, the first, for me to learn some ruby building something that at some point in my life I needed. The second, to build a toolthat is capable of encrypting/decrypting a file, whatever the size, initially using a ssh rsa/dsa public key. 

## The problem

Did you ever needed to send something encrypted to someone? in a really simple yet secure way?

Sure, some people would say, use a zip with a password, ok, and how do I give you the password securely? by email?

You can try using RSA encryption, but you will only get as far as something less than the key size, so it is not suitable for large files (by large I mean longer than 4k).

## The solution

Use GPG... yeah, but where is the fun in that?

So, basically my idea was to mimic SSL handshake using asymetric encryption to share a symmetric key, and then do it the other way around on the other side using the private key as a starting point.

This is how it would work in the real life:

1. User A sends his ssh public key to User B (~/.ssh/id_rsa.pub)
2. User B encrypts the file F using zssl and feeding it with User's A public key
3. User B sends the encrypted file to User A
4. User A decrypts the file F using zssl and feeding it with his ssh private key (~/.ssh/id_rsa)

This way the only shared cryptographic information is a public key, which is, as the name indicates, public.

## On technical implementation

The encrypted file will consist of two parts, one will be the shared key, which is hidden in a random byte array of the maximum possible size given the public key just to make it harder to break the async encryption (random in random is random).
And then a second part with the symmetric encrypted file, all encoded as base64 just to allow cutting an pasting the content in an email instead of using binary.

The rest is quite simple, classic RSA/DSA encryption and classic AES256 CBC encryption.

Enjoy, in case you need to actually send some encrypted data to somebody
