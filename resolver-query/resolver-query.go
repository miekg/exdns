//
// Example code using a public resolver to query AAAA records
//
package main

import (
    "fmt"

    "github.com/miekg/dns"
)

func main() {
    resolver := "8.8.8.8"
    domain := "netflix.com"

    client := dns.Client{}
    message := &dns.Msg{}
    message.RecursionDesired = true
    message.SetQuestion(domain + ".", dns.TypeAAAA) // Domains always have to end with a "."

    answer, _, err := client.Exchange(message, resolver + ":53") // IPv6 resolver IPs have to be enclosed in []

    if err != nil {
        fmt.Printf("Something went wrong while contacting the resolver: %s\n", err.Error())
    } else if answer.Rcode != dns.RcodeSuccess {
        fmt.Println("The resolver denied the request")
    } else {
        fmt.Printf("%s resolves to the following IPv6 adresses:\n", domain)

        for index, answer := range answer.Answer {
            if aaaa, ok := answer.(*dns.AAAA); ok {
                fmt.Printf("[%d] %s\n", index, aaaa.AAAA)
            } else {
                fmt.Println("[%d] Got something else than AAAA. Strange ...", index)
            }
        }
    }
}
