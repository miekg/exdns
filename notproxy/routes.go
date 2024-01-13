package main

import (
	"log"
	"net"

	"github.com/miekg/dns"
)

// Route holds the routing configuration. Per zone there is one "from" and one "to" address.
// TODO: extend to multiple addresses.
type Route struct {
	Zone string
	From net.IP
	To   net.IP
}

// Register registers a dns.Handler for each zone that routes DNS notifies.
func Register(rt Route) error {
	// Setup a conn for the lifetime of the server. Notifies are always UDP.
	connTo, err := dns.Dial("udp", rt.To.String()+":53")
	if err != nil {
		return err
	}
	connFrom, err := dns.Dial("udp", rt.From.String()+":53")
	if err != nil {
		return err
	}

	dns.HandleFunc(rt.Zone, func(w dns.ResponseWriter, r *dns.Msg) {
		if r.Opcode != dns.OpcodeNotify {
			log.Printf("Non notify seen for zone: %q", r.Question[0].Name)
			return
		}

		from, ok := w.RemoteAddr().(*net.UDPAddr)
		if !ok {
			log.Printf("Notify came in over TCP: dropping for zone: %q", r.Question[0].Name)
			return
		}
		// if from 'from' then forward to 'to'
		if rt.From.Equal(from.IP) {
			if err := connTo.WriteMsg(r); err != nil {
				log.Printf("Error while forwarding notify to %s for zone: %q: %s", rt.To, r.Question[0].Name, err)
			}
			return
		}

		// if from 'to' then forward to 'from'
		if rt.To.Equal(from.IP) {
			if err := connFrom.WriteMsg(r); err != nil {
				log.Printf("Error while forwarding notify to %s for zone: %q: %s", rt.From, r.Question[0].Name, err)
			}
			return
		}

		log.Printf("No routing found for %q for zone: %q", from.IP, r.Question[0].Name)
		// dropping request
	})
	return nil
}
