package dnsengine

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
)

var recordExplanations = map[uint16]string{
	dns.TypeA:      "Maps a hostname to an IPv4 address.",
	dns.TypeAAAA:   "Maps a hostname to an IPv6 address.",
	dns.TypeCNAME:  "Aliases this owner name to another canonical name.",
	dns.TypeMX:     "Selects a mail server; the lowest preference value is tried first.",
	dns.TypeNS:     "Delegates a zone or identifies one of its authoritative name servers.",
	dns.TypeSOA:    "Describes the zone authority, serial, refresh timers, and negative-cache policy.",
	dns.TypeTXT:    "Carries arbitrary text, commonly SPF, verification, and security policy data.",
	dns.TypePTR:    "Maps a reverse-DNS name back to a hostname.",
	dns.TypeSRV:    "Locates a service by priority, weight, port, and target host.",
	dns.TypeCAA:    "Restricts which certificate authorities may issue certificates for the name.",
	dns.TypeNAPTR:  "Applies ordered rewrite rules, often for SIP and other service discovery.",
	dns.TypeTLSA:   "Associates a TLS certificate or public key with a service through DANE.",
	dns.TypeSSHFP:  "Publishes SSH host-key fingerprints.",
	dns.TypeSVCB:   "Publishes service endpoints and connection parameters.",
	dns.TypeHTTPS:  "The HTTPS form of SVCB; can advertise alternate endpoints and HTTP capabilities.",
	dns.TypeDS:     "Links a child zone's DNSKEY to its signed parent, forming the DNSSEC chain of trust.",
	dns.TypeDNSKEY: "Publishes a zone's DNSSEC public key.",
	dns.TypeRRSIG:  "Contains a DNSSEC signature over an RRset.",
	dns.TypeNSEC:   "Proves non-existence in DNSSEC by linking ordered names and record types.",
	dns.TypeNSEC3:  "Proves non-existence using hashed names to reduce straightforward zone walking.",
	dns.TypeOPT:    "An EDNS pseudo-record that negotiates larger packets and extension options.",
}

var flagExplanations = map[string]string{
	"QR": "Query/Response: set when this message is a response.",
	"AA": "Authoritative Answer: the responding server is authoritative for the answer.",
	"TC": "Truncated: the response did not fit; retry over TCP.",
	"RD": "Recursion Desired: the client asked the server to resolve the full name.",
	"RA": "Recursion Available: the server offers recursive resolution.",
	"AD": "Authenticated Data: a validating recursive resolver says DNSSEC validation succeeded.",
	"CD": "Checking Disabled: the client asked the resolver not to reject DNSSEC failures.",
}

func recordsFromMessage(msg *dns.Msg) []Record {
	var out []Record
	appendSection := func(section string, records []dns.RR) {
		for _, rr := range records {
			h := rr.Header()
			typeName := typeString(h.Rrtype)
			text := rr.String()
			out = append(out, Record{
				Section: section, Name: h.Name, TTL: h.Ttl,
				Class: classString(h.Class), Type: typeName,
				Data: rrData(text), Text: text,
				Explanation: explainRecord(h.Rrtype),
			})
		}
	}
	appendSection("answer", msg.Answer)
	appendSection("authority", msg.Ns)
	appendSection("additional", msg.Extra)
	return out
}

func rrData(text string) string {
	fields := strings.Fields(text)
	if len(fields) < 5 {
		return text
	}
	return strings.Join(fields[4:], " ")
}

func explainRecord(t uint16) string {
	if text, ok := recordExplanations[t]; ok {
		return text
	}
	return "A DNS resource record. Its wire-format type is preserved even when the type is uncommon or experimental."
}

func flagsFromMessage(msg *dns.Msg) []Flag {
	values := []struct {
		code string
		on   bool
	}{
		{"QR", msg.Response}, {"AA", msg.Authoritative}, {"TC", msg.Truncated},
		{"RD", msg.RecursionDesired}, {"RA", msg.RecursionAvailable},
		{"AD", msg.AuthenticatedData}, {"CD", msg.CheckingDisabled},
	}
	out := make([]Flag, 0, len(values))
	for _, value := range values {
		out = append(out, Flag{Code: value.code, Enabled: value.on, Explanation: flagExplanations[value.code]})
	}
	return out
}

func ednsFromMessage(msg *dns.Msg) *EDNSInfo {
	opt := msg.IsEdns0()
	if opt == nil {
		return nil
	}
	info := &EDNSInfo{Version: opt.Version(), UDPSize: opt.UDPSize(), DNSSECOK: opt.Do(), ExtendedRcode: opt.ExtendedRcode()}
	for _, option := range opt.Option {
		info.Options = append(info.Options, option.String())
	}
	return info
}

func dnssecFromMessage(msg *dns.Msg, requested bool) DNSSECInfo {
	info := DNSSECInfo{Requested: requested, Authenticated: msg.AuthenticatedData, CheckingDisabled: msg.CheckingDisabled}
	all := append(append(append([]dns.RR{}, msg.Answer...), msg.Ns...), msg.Extra...)
	for _, rr := range all {
		switch rr.Header().Rrtype {
		case dns.TypeRRSIG:
			info.HasSignatures = true
		case dns.TypeNSEC, dns.TypeNSEC3:
			info.HasDenialProof = true
		case dns.TypeDS, dns.TypeDNSKEY:
			info.HasChainMaterial = true
		}
	}
	switch {
	case info.Authenticated:
		info.Status = "validated-by-resolver"
		info.Explanation = "The resolver set AD, reporting successful DNSSEC validation. Trust this only when the path to that resolver is trusted or encrypted."
	case info.HasSignatures:
		info.Status = "signed-not-locally-validated"
		info.Explanation = "DNSSEC signatures are present, but this observation alone does not prove a valid chain to the root trust anchor."
	case requested:
		info.Status = "unsigned-or-no-proof-returned"
		info.Explanation = "DNSSEC data was requested but no signature was observed in this response. The zone may be unsigned, or the requested RRset may not carry proof here."
	default:
		info.Status = "not-requested"
		info.Explanation = "Set the DNSSEC option to request signatures and denial-of-existence proofs."
	}
	return info
}

func responseExplanations(msg *dns.Msg, transport string, fromCache bool) []Explanation {
	rcode := rcodeString(msg.Rcode)
	out := []Explanation{{Subject: "Response code " + rcode, Text: explainRcode(msg.Rcode)}}
	if fromCache {
		out = append(out, Explanation{Subject: "Cache hit", Text: "No network query was sent. Remaining record TTLs were reduced to reflect time spent in the local WhereDNS cache."})
	} else {
		out = append(out, Explanation{Subject: "Transport " + strings.ToUpper(transport), Text: explainTransport(transport)})
	}
	if msg.Authoritative {
		out = append(out, Explanation{Subject: "Authoritative answer", Text: "The AA flag means the responder served this data from a zone for which it is authoritative."})
	}
	if msg.Truncated {
		out = append(out, Explanation{Subject: "Truncation", Text: "The TC flag indicates an incomplete response. WhereDNS retries an initial UDP query over TCP."})
	}
	return out
}

func explainRcode(code int) string {
	switch code {
	case dns.RcodeSuccess:
		return "NOERROR means the server processed the query. An empty answer can still be a valid NODATA response."
	case dns.RcodeNameError:
		return "NXDOMAIN means the queried name does not exist. The authority SOA normally controls negative caching."
	case dns.RcodeServerFailure:
		return "SERVFAIL means the server could not complete resolution; DNSSEC failure, timeout, or upstream failure are common causes."
	case dns.RcodeRefused:
		return "REFUSED means policy prevented the server from answering this client or query."
	case dns.RcodeFormatError:
		return "FORMERR means the server considered the DNS message malformed or unsupported."
	case dns.RcodeNotImplemented:
		return "NOTIMP means the server does not implement the requested operation."
	default:
		return fmt.Sprintf("DNS response code %d. Extended response codes may be carried through EDNS.", code)
	}
}

func explainTransport(transport string) string {
	switch strings.ToLower(transport) {
	case "udp":
		return "Classic DNS over UDP has low overhead but no confidentiality or peer authentication; large/truncated replies use TCP fallback."
	case "tcp":
		return "DNS over TCP provides reliable ordered delivery but is not encrypted."
	case "dot", "tls", "tcp-tls":
		return "DNS over TLS encrypts the connection to the selected resolver and normally uses port 853."
	case "doh", "https":
		return "DNS over HTTPS sends DNS wire messages inside authenticated HTTPS requests."
	default:
		return "The selected DNS transport carries a standard DNS wire message."
	}
}

func typeString(t uint16) string {
	if value, ok := dns.TypeToString[t]; ok {
		return value
	}
	return fmt.Sprintf("TYPE%d", t)
}

func classString(c uint16) string {
	if value, ok := dns.ClassToString[c]; ok {
		return value
	}
	return fmt.Sprintf("CLASS%d", c)
}

func rcodeString(code int) string {
	if value, ok := dns.RcodeToString[code]; ok {
		return value
	}
	return fmt.Sprintf("RCODE%d", code)
}
