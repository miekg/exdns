// Go equivalent of the "DNS & BIND" book check-soa program.
// Created by Stephane Bortzmeyer.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const (
	// DefaultTimeout is default timeout many operation in this program will
	// use.
	DefaultTimeout time.Duration = 5 * time.Second
)

var (
	localm *dns.Msg
	localc *dns.Client
	conf   *dns.ClientConfig
)

func localQuery(qname string, qtype uint16) (*dns.Msg, error) {
	localm.SetQuestion(qname, qtype)
	for _, server := range conf.Servers {
		r, _, err := localc.Exchange(localm, server+":"+conf.Port)
		if err != nil {
			return nil, err
		}
		if r == nil || r.Rcode == dns.RcodeNameError || r.Rcode == dns.RcodeSuccess {
			return r, err
		}
	}
	return nil, errors.New("No name server to answer the question")
}

func main() {
	if len(os.Args) != 2 {
		fmt.Printf("%s ZONE\n", os.Args[0])
		os.Exit(1)
	}
	var err error
	conf, err = dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || conf == nil {
		fmt.Printf("Cannot initialize the local resolver: %s\n", err)
		os.Exit(1)
	}
	localm = &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: make([]dns.Question, 1),
	}
	localc = &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	r, err := localQuery(dns.Fqdn(os.Args[1]), dns.TypeNS)
	if err != nil || r == nil {
		fmt.Printf("Cannot retrieve the list of name servers for %s: %s\n", dns.Fqdn(os.Args[1]), err)
		os.Exit(1)
	}
	if r.Rcode == dns.RcodeNameError {
		fmt.Printf("No such domain %s\n", dns.Fqdn(os.Args[1]))
		os.Exit(1)
	}
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: false,
		},
		Question: make([]dns.Question, 1),
	}
	c := &dns.Client{
		ReadTimeout: DefaultTimeout,
	}
	var success bool
	var numNS int
	for _, ans := range r.Answer {
		switch t := ans.(type) {
		case *dns.NS:
			nameserver := t.Ns
			numNS++
			var ips []string
			fmt.Printf("%s : ", nameserver)
			ra, err := localQuery(nameserver, dns.TypeA)
			if err != nil || ra == nil {
				fmt.Printf("Error getting the IPv4 address of %s: %s\n", nameserver, err)
				os.Exit(1)
			}
			if ra.Rcode != dns.RcodeSuccess {
				fmt.Printf("Error getting the IPv4 address of %s: %s\n", nameserver, dns.RcodeToString[ra.Rcode])
				os.Exit(1)
			}
			for _, ansa := range ra.Answer {
				switch ansb := ansa.(type) {
				case *dns.A:
					ips = append(ips, ansb.A.String())
				}
			}
			raaaa, err := localQuery(nameserver, dns.TypeAAAA)
			if err != nil || raaaa == nil {
				fmt.Printf("Error getting the IPv6 address of %s: %s\n", nameserver, err)
				os.Exit(1)
			}
			if raaaa.Rcode != dns.RcodeSuccess {
				fmt.Printf("Error getting the IPv6 address of %s: %s\n", nameserver, dns.RcodeToString[raaaa.Rcode])
				os.Exit(1)
			}
			for _, ansaaaa := range raaaa.Answer {
				switch tansaaaa := ansaaaa.(type) {
				case *dns.AAAA:
					ips = append(ips, tansaaaa.AAAA.String())
				}
			}
			if len(ips) == 0 {
				fmt.Printf("No IP address for this server")
			}
			for _, ip := range ips {
				m.Question[0] = dns.Question{Name: dns.Fqdn(os.Args[1]), Qtype: dns.TypeSOA, Qclass: dns.ClassINET}
				m.Id = dns.Id()
				var nsAddressPort string
				if strings.ContainsAny(":", ip) {
					// IPv6 address
					nsAddressPort = "[" + ip + "]:53"
				} else {
					nsAddressPort = ip + ":53"
				}
				soa, _, err := c.Exchange(m, nsAddressPort)
				// TODO: retry if timeout? Otherwise, one lost UDP packet and it is the end
				if err != nil || soa == nil {
					fmt.Printf("%s (%s) ", ip, err)
					goto Next
				}
				if soa.Rcode != dns.RcodeSuccess {
					fmt.Printf("%s (%s) ", ips, dns.RcodeToString[soa.Rcode])
					goto Next
				}
				if len(soa.Answer) == 0 { // May happen if the server is a recursor, not authoritative, since we query with RD=0
					fmt.Printf("%s (0 answer) ", ip)
					goto Next
				}
				rsoa := soa.Answer[0]
				switch trsoa := rsoa.(type) {
				case *dns.SOA:
					if soa.Authoritative {
						// TODO: test if all name servers have the same serial ?
						fmt.Printf("%s (%d) ", ips, trsoa.Serial)
					} else {
						fmt.Printf("%s (not authoritative) ", ips)
					}
				}
			}
			success = true
		Next:
			fmt.Printf("\n")
		}
	}
	if numNS == 0 {
		fmt.Printf("No NS records for %q. It is probably a CNAME to a domain but not a zone\n", dns.Fqdn(os.Args[1]))
		os.Exit(1)
	}
	if !success {
		os.Exit(1)
	}
}
