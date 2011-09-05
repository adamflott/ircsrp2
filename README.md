# What is IRCSRP? #

> IRCSRP is based on the SRP-6 protocol for password-authenticated key agreement. While SRP was originally designed for establishing a secure, authenticated channel between a user and a host, it can be adapted for group communications

Design and reference implementation by Björn [Edström](http://www.bjrn.se/ircsrp/)

Most instant messaging encryption plugins only support peer to peer level encryption. IRCSRP allows
an entire IRC channel to communicate securely. In fact this technique is not bound to the IRC
protocol. IRC was chosen for it’s wide availability and numerous scriptable clients.

# Current Operating System and Client Support #

* Linux with [Pidgin](http://pidgim.im) and [Weechat](http://www.weechat.org/)
* Windows with Pidgin and helper libraries (OpenSSL, GMP)
* You can use the existing Python[]() and [Perl](https://metacpan.org/module/Algorithm::IRCSRP2) libraries to implement in your preferred client
