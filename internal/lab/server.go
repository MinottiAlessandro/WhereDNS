package lab

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"

	"github.com/miekg/dns"
)

var serverScenarioNames = []string{"basic", "cache-poisoning", "rebinding", "tunneling", "lame-delegation"}

func ServerScenarios() []string { return append([]string(nil), serverScenarioNames...) }

// Serve starts a deliberately local-only UDP and TCP authoritative lab server.
func Serve(ctx context.Context, scenario, address string) error {
	if !validServerScenario(scenario) {
		return fmt.Errorf("unknown live-server scenario %q", scenario)
	}
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("the DNS laboratory server may bind only to an explicit loopback address")
	}

	handler := scenarioHandler(scenario)
	udp := &dns.Server{Addr: address, Net: "udp", Handler: handler}
	tcp := &dns.Server{Addr: address, Net: "tcp", Handler: handler}
	errorsCh := make(chan error, 2)
	go func() { errorsCh <- udp.ListenAndServe() }()
	go func() { errorsCh <- tcp.ListenAndServe() }()

	select {
	case <-ctx.Done():
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return nil
	case err := <-errorsCh:
		_ = udp.Shutdown()
		_ = tcp.Shutdown()
		return err
	}
}

func validServerScenario(value string) bool {
	for _, scenario := range serverScenarioNames {
		if scenario == value {
			return true
		}
	}
	return false
}

func scenarioHandler(scenario string) dns.Handler {
	var rebindCount atomic.Uint64
	return dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		if len(request.Question) == 0 {
			response.Rcode = dns.RcodeFormatError
			_ = w.WriteMsg(response)
			return
		}
		question := request.Question[0]
		name := strings.ToLower(question.Name)
		var lines []string
		switch scenario {
		case "basic":
			lines = basicRecords(name, question.Qtype)
		case "rebinding":
			if name == "rebind.test." && question.Qtype == dns.TypeA {
				address := "203.0.113.20"
				if rebindCount.Add(1)%2 == 0 {
					address = "127.0.0.1"
				}
				lines = []string{"rebind.test. 1 IN A " + address}
			}
		case "cache-poisoning":
			if strings.HasSuffix(name, ".poison.test.") || name == "poison.test." {
				lines = []string{name + " 30 IN A 192.0.2.10"}
				response.Extra = append(response.Extra, mustRR("bank.test. 600 IN A 192.0.2.66"))
			}
		case "tunneling":
			if strings.HasSuffix(name, ".tunnel.test.") && question.Qtype == dns.TypeTXT {
				lines = []string{name + " 5 IN TXT \"fixed-lab-response: inspect-label-entropy\""}
			}
		case "lame-delegation":
			if strings.HasSuffix(name, ".broken.test.") || name == "broken.test." {
				response.Authoritative = false
				response.Rcode = dns.RcodeRefused
			}
		}
		for _, line := range lines {
			response.Answer = append(response.Answer, mustRR(line))
		}
		if len(lines) == 0 && response.Rcode == dns.RcodeSuccess {
			response.Ns = append(response.Ns, mustRR("test. 60 IN SOA ns.test. hostmaster.test. 1 60 60 60 60"))
		}
		_ = w.WriteMsg(response)
	})
}

func basicRecords(name string, qtype uint16) []string {
	if name != "learn.test." {
		return nil
	}
	byType := map[uint16][]string{
		dns.TypeA:    {"learn.test. 60 IN A 192.0.2.10"},
		dns.TypeAAAA: {"learn.test. 60 IN AAAA 2001:db8::10"},
		dns.TypeNS:   {"learn.test. 60 IN NS ns.learn.test."},
		dns.TypeMX:   {"learn.test. 60 IN MX 10 mail.learn.test."},
		dns.TypeTXT:  {"learn.test. 60 IN TXT \"v=spf1 -all\"", "learn.test. 60 IN TXT \"WhereDNS isolated laboratory\""},
		dns.TypeCAA:  {"learn.test. 60 IN CAA 0 issue \"example.invalid\""},
		dns.TypeSOA:  {"learn.test. 60 IN SOA ns.learn.test. hostmaster.learn.test. 2026081001 3600 600 86400 60"},
	}
	if qtype == dns.TypeANY {
		var all []string
		for _, lines := range byType {
			all = append(all, lines...)
		}
		return all
	}
	return byType[qtype]
}

func mustRR(value string) dns.RR {
	rr, err := dns.NewRR(value)
	if err != nil {
		panic(err)
	}
	return rr
}
