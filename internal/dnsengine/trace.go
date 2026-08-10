package dnsengine

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type rootHint struct {
	Name string
	IPv4 string
	IPv6 string
}

// Root hints are stable protocol bootstrap data published by IANA.
var rootHints = []rootHint{
	{"a.root-servers.net.", "198.41.0.4", "2001:503:ba3e::2:30"},
	{"b.root-servers.net.", "170.247.170.2", "2801:1b8:10::b"},
	{"c.root-servers.net.", "192.33.4.12", "2001:500:2::c"},
	{"d.root-servers.net.", "199.7.91.13", "2001:500:2d::d"},
	{"e.root-servers.net.", "192.203.230.10", "2001:500:a8::e"},
	{"f.root-servers.net.", "192.5.5.241", "2001:500:2f::f"},
	{"g.root-servers.net.", "192.112.36.4", "2001:500:12::d0d"},
	{"h.root-servers.net.", "198.97.190.53", "2001:500:1::53"},
	{"i.root-servers.net.", "192.36.148.17", "2001:7fe::53"},
	{"j.root-servers.net.", "192.58.128.30", "2001:503:c27::2:30"},
	{"k.root-servers.net.", "193.0.14.129", "2001:7fd::1"},
	{"l.root-servers.net.", "199.7.83.42", "2001:500:9f::42"},
	{"m.root-servers.net.", "202.12.27.33", "2001:dc3::35"},
}

// Trace performs iterative resolution: root -> TLD -> authoritative server.
func (e *Engine) Trace(ctx context.Context, options QueryOptions) (*TraceResult, error) {
	started := time.Now()
	name, err := NormalizeName(options.Name)
	if err != nil {
		return nil, err
	}
	_, qtypeName, err := ParseType(options.Type)
	if err != nil {
		return nil, err
	}
	trace := &TraceResult{Name: name, Type: qtypeName, StartedAt: started}
	currentName := name
	servers := []serverCandidate{{Name: rootHints[0].Name, Address: rootHints[0].IPv4, Role: "root"}}
	seen := make(map[string]bool)
	cnameCount := 0

	for hop := 1; hop <= 24; hop++ {
		var msg *dns.Msg
		var result *Result
		var used serverCandidate
		var queryErr error
		for _, candidate := range servers {
			stepOptions := options
			stepOptions.Name = currentName
			stepOptions.Type = qtypeName
			stepOptions.Server = net.JoinHostPort(candidate.Address, "53")
			stepOptions.Transport = "udp"
			stepOptions.RecursionDesired = false
			stepOptions.Timeout = minDuration(options.Timeout, 4*time.Second)
			msg, result, queryErr = e.queryMessage(ctx, stepOptions)
			if queryErr == nil {
				used = candidate
				break
			}
		}
		if queryErr != nil {
			return trace, fmt.Errorf("all candidate name servers failed at hop %d: %w", hop, queryErr)
		}

		step := TraceStep{
			Number: hop, Role: used.Role, Server: used.Name, Address: used.Address,
			Question: currentName + " " + qtypeName, Rcode: result.Rcode,
			DurationMS: result.DurationMS, FromCache: result.FromCache,
			Transport: result.Transport, ResponseBytes: result.Wire.ResponseBytes,
			Records: result.Records,
		}
		if msg.Rcode != dns.RcodeSuccess {
			step.Event = result.Rcode
			step.Explanation = explainRcode(msg.Rcode)
			trace.Steps = append(trace.Steps, step)
			trace.Complete = true
			trace.DurationMS = float64(time.Since(started).Microseconds()) / 1000
			return trace, nil
		}

		if hasAnswer(msg, qtypeName) {
			step.Event = "final answer"
			step.Explanation = "This server returned the requested RRset. The iterative walk is complete."
			trace.Steps = append(trace.Steps, step)
			trace.Complete = true
			trace.DurationMS = float64(time.Since(started).Microseconds()) / 1000
			return trace, nil
		}

		if target, ok := cnameTarget(msg); ok {
			cnameCount++
			if cnameCount > 8 {
				return trace, fmt.Errorf("CNAME chain exceeded eight redirects")
			}
			step.Event = "CNAME redirect"
			step.Explanation = "The name is an alias. Resolution restarts at the root for the canonical target " + target
			trace.Steps = append(trace.Steps, step)
			currentName = target
			servers = []serverCandidate{{Name: rootHints[cnameCount%len(rootHints)].Name, Address: rootHints[cnameCount%len(rootHints)].IPv4, Role: "root"}}
			continue
		}

		zone, nsNames := referral(msg)
		if len(nsNames) == 0 {
			step.Event = "NODATA"
			step.Explanation = "The server returned NOERROR but neither the requested type nor a referral. The name may exist without this record type."
			trace.Steps = append(trace.Steps, step)
			trace.Complete = true
			trace.DurationMS = float64(time.Since(started).Microseconds()) / 1000
			return trace, nil
		}
		loopKey := strings.ToLower(zone + "|" + strings.Join(nsNames, ","))
		if seen[loopKey] {
			return trace, fmt.Errorf("delegation loop detected for zone %s", zone)
		}
		seen[loopKey] = true
		candidates, allInBailiwick := glueCandidates(msg, zone, nsNames)
		if len(candidates) == 0 {
			candidates, err = e.bootstrapNameservers(ctx, nsNames)
			if err != nil {
				return trace, fmt.Errorf("referral for %s had no usable glue: %w", zone, err)
			}
			step.Explanation = "Referral to " + zone + ". No in-bailiwick glue was available, so the name-server address was bootstrapped through the configured recursive resolver."
		} else if allInBailiwick {
			step.Explanation = "Referral to " + zone + ". In-bailiwick glue supplies an address for the next authoritative server."
		} else {
			step.Explanation = "Referral to " + zone + ". The matching Additional-section address is outside the child bailiwick, so it is used only as a routing hint and is not treated as authoritative cache data."
		}
		role := "authoritative"
		if dns.CountLabel(zone) == 1 {
			role = "TLD"
		}
		for i := range candidates {
			candidates[i].Role = role
		}
		step.Event = "delegation to " + zone
		trace.Steps = append(trace.Steps, step)
		servers = candidates
	}
	return trace, fmt.Errorf("iterative trace exceeded 24 hops")
}

type serverCandidate struct {
	Name    string
	Address string
	Role    string
}

func referral(msg *dns.Msg) (string, []string) {
	zone := ""
	var names []string
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			if zone == "" {
				zone = ns.Hdr.Name
			}
			names = append(names, ns.Ns)
		}
	}
	return zone, names
}

func glueCandidates(msg *dns.Msg, zone string, nsNames []string) ([]serverCandidate, bool) {
	allowed := make(map[string]bool)
	for _, name := range nsNames {
		allowed[strings.ToLower(name)] = true
	}
	var out []serverCandidate
	allInBailiwick := true
	for _, rr := range msg.Extra {
		switch value := rr.(type) {
		case *dns.A:
			if allowed[strings.ToLower(value.Hdr.Name)] {
				out = append(out, serverCandidate{Name: value.Hdr.Name, Address: value.A.String()})
				allInBailiwick = allInBailiwick && dns.IsSubDomain(zone, value.Hdr.Name)
			}
		case *dns.AAAA:
			if allowed[strings.ToLower(value.Hdr.Name)] {
				out = append(out, serverCandidate{Name: value.Hdr.Name, Address: value.AAAA.String()})
				allInBailiwick = allInBailiwick && dns.IsSubDomain(zone, value.Hdr.Name)
			}
		}
	}
	if len(out) > 8 {
		out = out[:8]
	}
	return out, allInBailiwick
}

func (e *Engine) bootstrapNameservers(ctx context.Context, names []string) ([]serverCandidate, error) {
	var out []serverCandidate
	for _, name := range names {
		addresses, err := net.DefaultResolver.LookupHost(ctx, strings.TrimSuffix(name, "."))
		if err != nil {
			continue
		}
		for _, address := range addresses {
			out = append(out, serverCandidate{Name: name, Address: address})
			if len(out) >= 8 {
				return out, nil
			}
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("could not resolve any of %s", strings.Join(names, ", "))
	}
	return out, nil
}

func hasAnswer(msg *dns.Msg, qtypeName string) bool {
	wanted, _, err := ParseType(qtypeName)
	if err != nil {
		return false
	}
	for _, rr := range msg.Answer {
		if rr.Header().Rrtype == wanted {
			return true
		}
	}
	return false
}

func cnameTarget(msg *dns.Msg) (string, bool) {
	for _, rr := range msg.Answer {
		if cname, ok := rr.(*dns.CNAME); ok {
			return cname.Target, true
		}
	}
	return "", false
}

func minDuration(value, maximum time.Duration) time.Duration {
	if value <= 0 || value > maximum {
		return maximum
	}
	return value
}
