# ZSSL

### Status
[![Build Status](https://travis-ci.org/pcarranza/zssl.png)](https://travis-ci.org/pcarranza/zssl)
[![Coverage Status](https://coveralls.io/repos/pcarranza/zssl/badge.png)](https://coveralls.io/r/pcarranza/zssl)

## SSL like encryption for secure file sharing

### Excerpt

Large file encryption/decryption based on ssh RSA public/private key and AES 256 CBC

### Summary

This project covers two big goals: 

* The first, for me to learn some ruby coding while building something that I needed at some point in my life. 
* The second, to create a tool that is capable of encrypting/decrypting a file, whatever the size, initially using a ssh rsa public key for encryption, like the one you use to access remote servers by ssh: your ~/.ssh/id_rsa.pub

## The problem

Did you ever needed to send something encrypted to someone? in a really simple yet secure way?

Sure, some people would say, use a zip with a password; ok, and how do I send you the password securely? by email? should I call you to give you the password so we don't share it publicly? That solution is obviously not good.

You can try RSA encryption, but you will only be able to encrypt something smaller than the key size, so it is not suitable for large files (by large I mean longer than 4k).

There's also smime encryption, you can email the file using some certificate, you only need an email client that can handle encrypted files, and a smime valid certificate. But even then you will hit a memory limit, and whatever the limit of your mailing system is.
Also, that could not be done if you use gmail or any other web based email system. So it's not a good option, at last not for me.

## The solution

Basically my idea is to mimic how the SSL handshake works using asymetric encryption to share a symmetric key, and then do it the other way around on the other side using the private key as a starting point. An idea that everybody will propose, but I never found a simple solution that does this in one instruction.

This is how it would work in the real life:

1. User A sends his ssh public key to User B (~/.ssh/id_rsa.pub)
2. User B encrypts the file F using zssl and feeding it with User's A public key
3. User B sends the encrypted file to User A in any way he prefers
4. User A decrypts the file F using zssl and feeding it with his ssh private key (~/.ssh/id_rsa)

This way the only shared cryptographic information is a RSA public key, which is, as the name indicates, public. Also the RSA key will only be used to encrypt one symmetric random shared key that will be used once, the rest of the file will be encrypted using AES 256 CBC, so no Watermark attack possible.

## How to use it

Encryption using user A public key

    user_b] zssl -i ~/Documents/keys/user_A_id_rsa.pub e ~/my_super_super_secret_document my_encrypted_document

Decryption using default ssh private key

    user_a] zssl d ~/my_encrypted_document my_decrypted_document

The app also supports reading from stdin and writing to stdout, like this:
    
    user_a] zssl d < my_encrypted_document > my_decrypted_document

## How to install

The usual for git and ruby

    git clone ...
    cd ...
    gem build zssl.gemspec
    gem install zssl-0.0.1.gem

## Quick test in a one-liner

`F=~/a_file_to_test ; expected=$(md5 < $F) ; zssl e < $F > ~/testfile ; result=$(zssl d < ~/testfile | md5) ; if [ "$expected"="$result" ]; then echo "All good" ; else echo "Something went went wrong: $expected != $result" ; fi`

## TODO

I'm still working on it, and would probably provide a homebrew formula for the lazy people like me.

## On technical implementation

The encrypted file will consist of two parts, one will be the shared key, which is hidden in a random byte array of the maximum possible size given the public key just to make it harder to break the async encryption (random in random is random).
And then a second part with the symmetric encrypted file, all encoded as base64 just to allow cutting an pasting the content in an email instead of using binary.

The rest is quite simple, classic RSA encryption and classic AES 256 CBC encryption. Like you did all your life with OpenSSL, but all in one place and with one tool only, and using a buffer as large as 1Kb, so the memory footprint is quite reduced.

And finally, I'm encoding the file to base64, first because that simplifies the parsing, and because it is always easier to handle text files instead of binary. I know it will make the file bigger, but also there are fantastic compression tools that can handle compressing base64 text to a very minimal if size really matters (like 7zip).

Enjoy, in case you do need to send some encrypted data to somebody, now you have a simple way of doing it.

## Thanks to

* [mjwhitta](http://stackoverflow.com/users/1224550/mjwhitta) for sharing how to read an ssh public key in [this stackoverflow post](http://stackoverflow.com/questions/20751947/how-to-read-id-rsa-pub-into-ruby-bignum)
