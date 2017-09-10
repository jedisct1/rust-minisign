# rsign #
[ ![Codeship Status for danielrangel/rsign](https://app.codeship.com/projects/60b28d80-7645-0135-4402-1639b58199d0/status?branch=master)](https://app.codeship.com/projects/244452)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)


A simple rust implementation of [Minisign](https://jedisct1.github.io/minisign/) tool


Tarballs and pre-compiled binaries can be verified with the following
public key:

    RWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3

Compilation / installation
--------------------------

Dependencies:
* [libsodium](http://doc.libsodium.org/)

Compilation:

    $ git clone https://danielrangel@bitbucket.org/danielrangel/rsign.git
    $ cd rsign
    $ cargo build --release
    $ 


Usage
----------------

    $ rsign generate

Generates a new key pair. The public key is printed in the screen and stored in _rsign.pub_ by default. The secret key is writen at _~/.rsign/rsign.key_. You can change the default paths with -p and -s respectively. 

    $ rsign sign myfile.txt

Sign _myfile.txt_ with your secret key. You can add a trusted comment that will also be signed with:

    $ rsign sign myfile.txt -t "my trusted comment""

And to verify the signature with a given public key you can use:

    $ rsign verify myfile.txt -p rsign.pub

Or if you have saved the signature file with a custom name other than _myfile.txt.rsign_ and want to use a public key string you can use:

    $ rsign verify myfile.txt -P [PUBLIC KEY STRING] -x mysignature.file    

