> [!WARNING]
> **DEPRECATED**
> This repository is no longer supported or maintained. The new ConnectBot SSH library can be found at [https://github.com/connectbot/sshlib](https://github.com/connectbot/sshlib).
>
> This former library was based on Trilead SSH-2. If you still need a maintained version of the Trilead library, please refer to [https://github.com/jenkinsci/trilead-ssh2](https://github.com/jenkinsci/trilead-ssh2).

# Trilead SSH-2 library **(formerly used in ConnectBot)**
[![Build Status](https://github.com/connectbot/trilead-ssh2/actions/workflows/ci.yml/badge.svg)](https://github.com/connectbot/trilead-ssh2/actions/workflows/ci.yml)
[![Download](https://img.shields.io/maven-central/v/org.connectbot/sshlib)](https://search.maven.org/artifact/org.connectbot/sshlib)

This was ConnectBot's SSH library. It started as a continuation of the Trilead SSH2 library,
but had several features added to it.

This library retains its original [3-Clause BSD license](
https://opensource.org/licenses/BSD-3-Clause).

##### Encryption:
  * `chacha20-poly1305@openssh.com` ([draft-ietf-sshm-chacha20-poly1305](https://datatracker.ietf.org/doc/html/draft-ietf-sshm-chacha20-poly1305))
  * `aes256-gcm@openssh.com` ([RFC 5647](https://tools.ietf.org/html/rfc5647), [draft-miller-sshm-aes-gcm](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm))
  * `aes128-gcm@openssh.com` ([RFC 5647](https://tools.ietf.org/html/rfc5647), [draft-miller-sshm-aes-gcm](https://datatracker.ietf.org/doc/html/draft-miller-sshm-aes-gcm))
  * `aes256-ctr` ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
  * `aes128-ctr` ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
  * `aes256-cbc` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3))
  * `aes128-cbc` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3))
  * `blowfish-ctr` ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
  * `blowfish-cbc` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3))
  * `3des-ctr` ([RFC 4344](https://tools.ietf.org/html/rfc4344#section-4))
  * `3des-cbc` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.3))

##### MACs:
  * `hmac-sha2-512-etm@openssh.com` ([OpenSSH PROTOCOL](
    https://github.com/openssh/openssh-portable/blob/e1b26ce504662a5d5b991091228984ccfd25f280/PROTOCOL#L54))
  * `hmac-sha2-256-etm@openssh.com` ([OpenSSH PROTOCOL](
    https://github.com/openssh/openssh-portable/blob/e1b26ce504662a5d5b991091228984ccfd25f280/PROTOCOL#L54))
  * `hmac-sha1-etm@openssh.com` ([OpenSSH PROTOCOL](
    https://github.com/openssh/openssh-portable/blob/e1b26ce504662a5d5b991091228984ccfd25f280/PROTOCOL#L54))
  * `hmac-sha2-512` ([RFC 4868](https://tools.ietf.org/html/rfc4868))
  * `hmac-sha2-256` ([RFC 4868](https://tools.ietf.org/html/rfc4868))
  * `hmac-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.4))
  
##### Key support:
  * Ed25519 ([RFC 8709](https://tools.ietf.org/html/rfc8709))
  * ECDSA ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-3))
  * RSA  ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-6.6))

##### Key exchange:
  * `mlkem768x25519-sha256` ([draft-ietf-sshm-mlkem-hybrid-kex](https://datatracker.ietf.org/doc/draft-ietf-sshm-mlkem-hybrid-kex/) (depends on JEP-496 support))
  * `ecdh-sha2-nistp521` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
  * `ecdh-sha2-nistp384` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
  * `ecdh-sha2-nistp256` ([RFC 5656](https://tools.ietf.org/html/rfc5656#section-4))
  * `curve25519-sha256` ([RFC 8731](https://tools.ietf.org/html/rfc8731))
  * `diffie-hellman-group18-sha512` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
  * `diffie-hellman-group16-sha512` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
  * `diffie-hellman-group14-sha256` ([RFC 8268](https://tools.ietf.org/html/rfc8268))
  * `diffie-hellman-group-exchange-sha256` ([RFC 4419](https://tools.ietf.org/html/rfc4419))
  * `diffie-hellman-group-exchange-sha1` ([RFC 4419](https://tools.ietf.org/html/rfc4419))
  * `diffie-hellman-group14-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1))
  * `diffie-hellman-group1-sha1` ([RFC 4253](https://tools.ietf.org/html/rfc4253#section-8.1))
