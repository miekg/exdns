# notprox

A DNS notify proxy server. See route.go for the routing of the notifies.
It purely proxies, meaning the server itself doesn't send replies, it requires
that the server the notify is sent too, will send a notify response.

See RFC 1996 for DNS notifies.

Not done and problems one can forsee:

* TSIG key configuration

Tested with `dig @localhost -p 8053 SOA +aa +norec +opcode=notify miek.nl`
