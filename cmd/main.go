package main

import (
	"bytes"
	"fmt"
	"net/netip"
	"os"

	"github.com/BPplays/dns_check"
)


func main() {
	remote_test := []string{"google.com", "facebook.com"}

	var br bytes.Buffer

	fws := []dns_check.ForwarderGroup{

		dns_check.ForwarderGroup{
			Name: "test invalid",
			Forwarders:
			[]dns_check.Forwarder{
				{
					Server: netip.MustParseAddrPort("[::11]:53"),
					Test_domains: remote_test,
					Ftype: dns_check.ForwarderTypeDNS,
				},
			},
			Opts: dns_check.DefaultDnsOpts(),
		},

		dns_check.ForwarderGroup{
			Name: "quad 9",
			Forwarders:
			[]dns_check.Forwarder{
				{
					Server: netip.MustParseAddrPort("[2620:fe::11]:53"),
					Test_domains: remote_test,
					Ftype: dns_check.ForwarderTypeDNS,
				},

				{
					Server: netip.MustParseAddrPort("[2620:fe::fe:11]:53"),
					Test_domains: remote_test,
					Ftype: dns_check.ForwarderTypeDNS,
				},
			},
			Opts: dns_check.DefaultDnsOpts(),
		},


		dns_check.ForwarderGroup{
			Name: "google public dns",
			Forwarders:
			[]dns_check.Forwarder{
				{
					Server: netip.MustParseAddrPort("[2001:4860:4860::8888]:53"),
					Test_domains: remote_test,
					Ftype: dns_check.ForwarderTypeDNS,
				},

				{
					Server: netip.MustParseAddrPort("[2001:4860:4860::8844]:53"),
					Test_domains: remote_test,
					Ftype: dns_check.ForwarderTypeDNS,
				},
			},
			Opts: dns_check.DefaultDnsOpts(),
		},

	}

	c := dns_check.Config{
		Forwarders: fws,
		LogWriter: &br,
	}
	fInt, err := dns_check.Run(c)
	fmt.Println("===  logs  ===")
	fmt.Print(br.String())
	fmt.Println("=== /logs  ===")

	if err != nil {
		fmt.Printf("error: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("found: %v\n", fws[fInt].Name)
}
