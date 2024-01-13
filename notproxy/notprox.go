// Copyright 2024 Miek Gieben. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// A notify proxy server.

package main

import (
	"flag"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/miekg/dns"
)

// routes holds all the routing information.
var routes = []Route{
	{Zone: "miek.nl.", From: net.ParseIP("127.0.0.1"), To: net.ParseIP("10.10.0.1")},
}

func main() {
	port := flag.Int("port", 8053, "port to run on")
	flag.Parse()

	for i := range routes {
		err := Register(routes[i])
		if err != nil {
			log.Fatalf("Failed to register route for: %q: %s", routes[i].Zone, err)
		}
		log.Printf("Registered route for zone: %q", routes[i].Zone)
	}

	go func() {
		srv := &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "udp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set udp listener: %s", err.Error())
		}
	}()

	// technically we don't need to listen on TCP
	go func() {
		srv := &dns.Server{Addr: ":" + strconv.Itoa(*port), Net: "tcp"}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set tcp listener: %s", err.Error())
		}
	}()

	log.Printf("Ready for foward notifies on port %d", *port)

	sig := make(chan os.Signal)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	s := <-sig
	log.Fatalf("Signal (%v) received, stopping", s)
}
