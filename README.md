# ZSSL

### Status
[![Build Status](https://travis-ci.org/pcarranza/zssl.png)](https://travis-ci.org/pcarranza/zssl)
[![Coverage Status](https://coveralls.io/repos/pcarranza/zssl/badge.png)](https://coveralls.io/r/pcarranza/zssl)

Description
--------------------

Enveloped encryption for secure file sharing based on ssh RSA keypairs

Synopsis
--------------------

``` bash
myhost ~$ zssl -i your_ssh_key.pub e file_to_share.plain file_to_share.encrypted

yourhost ~$ zssl d file_to_share.encrypted file_to_share.decrypted
```

Install
--------------------

gem install zssl

Parameters
--------------------

--identity, -i

The first and second arguments will be replaced with *stdin* and *stdout* respectively if not provided.

Principles and goals
--------------------

* Share files of any size through email without installing PGP, or S/Mime
* Or whatever transport you want to use
* No need to install drivers or obscure OS features
* Make it a reusable gem to use ssh RSA key encryption in any project

Acceptance test
--------------------

`F=~/a_file_to_test ; expected=$(md5 < $F) ; zssl e < $F > ~/testfile ; result=$(zssl d < ~/testfile | md5) ; if [ "$expected"="$result" ]; then echo "All good" ; else echo "Something went wrong: $expected != $result" ; fi`
