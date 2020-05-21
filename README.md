# Kong Go Plugins

[Kong](https://konghq.com) plugins written in Go. This repo contains some
of examples to get you started:

* **go-hello**: a "hello world" plugin, which reads a request header
  and sets a response header.
* **go-log**: a reimplementation of Kong's `file-log` plugin in Go.
* **go-jwe**: a JWE (Json Web Encrypted token) decrypter plugin, which reads a Bearer Authorization with an encrypted token (following JWE standard)
and replaces with the decrypted text (normally a JWS signed JWT token). This plugin can be combined with jwt-tokens plugin of Kong standard distribution.
