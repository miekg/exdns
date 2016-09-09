// Copyright 2011 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Chaos is a small program that prints the version.bind and hostname.bind
// for each address of the nameserver given as argument.
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"

	"github.com/miekg/dns"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf("%s NAMESERVER\n", os.Args[0])
	}
	conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		log.Fatal("error making client from default file", err)
	}

	m := &dns.Msg{
		Question: make([]dns.Question, 1),
	}

	c := new(dns.Client)

	addr := addresses(conf, c, os.Args[1])
	if len(addr) == 0 {
		log.Fatalf("No address found for %s\n", os.Args[1])
	}
	for _, a := range addr {
		m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, rtt, err := c.Exchange(m, a)
		if err != nil {
			fmt.Println(err)
		}
		if in != nil && len(in.Answer) > 0 {
			log.Printf("(time %.3d µs) %v\n", rtt/1e3, in.Answer[0])
		}
		m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
		in, rtt, err = c.Exchange(m, a)
		if err != nil {
			fmt.Println(err)
		}
		if in != nil && len(in.Answer) > 0 {
			log.Printf("(time %.3d µs) %v\n", rtt/1e3, in.Answer[0])
		}
	}
}

func do(t chan *dns.Msg, wg *sync.WaitGroup, c *dns.Client, m *dns.Msg, addr string) {
	defer wg.Done()
	r, _, err := c.Exchange(m, addr)
	if err != nil {
		fmt.Println(err)
		return
	}
	t <- r
}

func addresses(conf *dns.ClientConfig, c *dns.Client, name string) (ips []string) {
	m4 := new(dns.Msg)
	m4.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeA)
	m6 := new(dns.Msg)
	m6.SetQuestion(dns.Fqdn(os.Args[1]), dns.TypeAAAA)
	t := make(chan *dns.Msg, 2)

	wg := new(sync.WaitGroup)
	wg.Add(2)
	go do(t, wg, c, m4, net.JoinHostPort(conf.Servers[0], conf.Port))
	go do(t, wg, c, m6, net.JoinHostPort(conf.Servers[0], conf.Port))
	wg.Wait()
	close(t)

	for d := range t {
		if d.Rcode == dns.RcodeSuccess {
			for _, a := range d.Answer {
				switch t := a.(type) {
				case *dns.A:
					ips = append(ips, net.JoinHostPort(t.A.String(), "53"))
				case *dns.AAAA:
					ips = append(ips, net.JoinHostPort(t.AAAA.String(), "53"))

				}
			}
		}
	}

	return ips
}
