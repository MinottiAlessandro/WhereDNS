package dnsengine

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/idna"
)

type Engine struct {
	Cache      *Cache
	HTTPClient *http.Client
}

func New(cache *Cache) *Engine {
	if cache == nil {
		cache, _ = NewCache("")
	}
	return &Engine{
		Cache:      cache,
		HTTPClient: &http.Client{Timeout: 8 * time.Second},
	}
}

func DefaultOptions(name string) QueryOptions {
	return QueryOptions{
		Name: name, Type: "A", Transport: "udp", UseCache: true,
		DNSSEC: true, RecursionDesired: true, EDNSSize: 1232, Timeout: 5 * time.Second,
	}
}

func ParseType(value string) (uint16, string, error) {
	value = strings.ToUpper(strings.TrimSpace(value))
	if value == "" {
		value = "A"
	}
	if t, ok := dns.StringToType[value]; ok {
		return t, value, nil
	}
	if strings.HasPrefix(value, "TYPE") {
		n, err := strconv.ParseUint(strings.TrimPrefix(value, "TYPE"), 10, 16)
		if err == nil {
			return uint16(n), value, nil
		}
	}
	return 0, "", fmt.Errorf("unknown DNS type %q; use a mnemonic such as A or TYPE65", value)
}

func NormalizeName(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", errors.New("query name is required")
	}
	name = strings.TrimSuffix(name, ".")
	ascii, err := idna.Lookup.ToASCII(name)
	if err != nil {
		return "", fmt.Errorf("invalid internationalized domain name: %w", err)
	}
	if _, ok := dns.IsDomainName(ascii); !ok {
		return "", fmt.Errorf("invalid DNS name %q", name)
	}
	return dns.Fqdn(strings.ToLower(ascii)), nil
}

func DefaultResolver() (string, error) {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("read system resolver: %w", err)
	}
	if len(config.Servers) == 0 {
		return "", errors.New("no nameserver found in /etc/resolv.conf")
	}
	port := config.Port
	if port == "" {
		port = "53"
	}
	return net.JoinHostPort(config.Servers[0], port), nil
}

func (e *Engine) Query(ctx context.Context, opts QueryOptions) (*Result, error) {
	msg, result, err := e.queryMessage(ctx, opts)
	_ = msg
	return result, err
}

func (e *Engine) queryMessage(ctx context.Context, opts QueryOptions) (*dns.Msg, *Result, error) {
	name, err := NormalizeName(opts.Name)
	if err != nil {
		return nil, nil, err
	}
	qtype, qtypeName, err := ParseType(opts.Type)
	if err != nil {
		return nil, nil, err
	}
	opts.Name, opts.Type = name, qtypeName
	if opts.Timeout <= 0 {
		opts.Timeout = 5 * time.Second
	}
	if opts.EDNSSize == 0 {
		opts.EDNSSize = 1232
	}
	transport := strings.ToLower(strings.TrimSpace(opts.Transport))
	if transport == "" {
		transport = "udp"
	}
	server, tlsName, err := normalizeServer(opts.Server, transport)
	if err != nil {
		return nil, nil, err
	}

	request := new(dns.Msg)
	request.SetQuestion(name, qtype)
	request.RecursionDesired = opts.RecursionDesired
	request.CheckingDisabled = opts.CheckingDisabled
	request.SetEdns0(opts.EDNSSize, opts.DNSSEC)
	queryWire, err := request.Pack()
	if err != nil {
		return nil, nil, fmt.Errorf("encode DNS query: %w", err)
	}
	key := cacheKey(opts, name, qtypeName, server, transport)
	if opts.UseCache {
		wire, expires, hit, cacheErr := e.Cache.Get(key)
		if cacheErr != nil {
			return nil, nil, fmt.Errorf("read cache: %w", cacheErr)
		}
		if hit {
			cached := new(dns.Msg)
			if err := cached.Unpack(wire); err == nil {
				remaining := time.Until(expires)
				ageTTLs(cached, remaining)
				result := buildResult(cached, opts, server, transport, queryWire, wire, 0, true, key, &expires)
				return cached, result, nil
			}
		}
	}

	queryCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()
	start := time.Now()
	response, rtt, responseWire, actualTransport, err := e.exchange(queryCtx, request, server, tlsName, transport)
	if err != nil {
		return nil, nil, fmt.Errorf("DNS query %s %s via %s to %s: %w", name, qtypeName, transport, server, err)
	}
	if rtt <= 0 {
		rtt = time.Since(start)
	}
	if len(responseWire) == 0 {
		responseWire, _ = response.Pack()
	}
	var expires *time.Time
	if opts.UseCache {
		if ttl := messageTTL(response); ttl > 0 {
			exp := time.Now().Add(time.Duration(ttl) * time.Second)
			expires = &exp
			if err := e.Cache.Put(key, name, qtypeName, server, responseWire, ttl); err != nil {
				return nil, nil, fmt.Errorf("save cache: %w", err)
			}
		}
	}
	result := buildResult(response, opts, server, actualTransport, queryWire, responseWire, rtt, false, key, expires)
	return response, result, nil
}

func (e *Engine) exchange(ctx context.Context, request *dns.Msg, server, tlsName, transport string) (*dns.Msg, time.Duration, []byte, string, error) {
	switch transport {
	case "udp", "tcp":
		client := &dns.Client{Net: transport}
		response, rtt, err := client.ExchangeContext(ctx, request, server)
		if err != nil {
			return nil, 0, nil, transport, err
		}
		actual := transport
		if transport == "udp" && response.Truncated {
			client.Net = "tcp"
			response, rtt, err = client.ExchangeContext(ctx, request, server)
			actual = "tcp (UDP fallback)"
		}
		if err != nil {
			return nil, 0, nil, actual, err
		}
		wire, _ := response.Pack()
		return response, rtt, wire, actual, nil
	case "dot", "tls", "tcp-tls":
		client := &dns.Client{Net: "tcp-tls", TLSConfig: &tls.Config{ServerName: tlsName, MinVersion: tls.VersionTLS12}}
		response, rtt, err := client.ExchangeContext(ctx, request, server)
		if err != nil {
			return nil, 0, nil, "dot", err
		}
		wire, _ := response.Pack()
		return response, rtt, wire, "dot", nil
	case "doh", "https":
		return e.exchangeDoH(ctx, request, server)
	default:
		return nil, 0, nil, transport, fmt.Errorf("unsupported transport %q (use udp, tcp, dot, or doh)", transport)
	}
}

func (e *Engine) exchangeDoH(ctx context.Context, request *dns.Msg, endpoint string) (*dns.Msg, time.Duration, []byte, string, error) {
	wire, err := request.Pack()
	if err != nil {
		return nil, 0, nil, "doh", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(wire))
	if err != nil {
		return nil, 0, nil, "doh", err
	}
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("Content-Type", "application/dns-message")
	start := time.Now()
	resp, err := e.HTTPClient.Do(req)
	if err != nil {
		return nil, 0, nil, "doh", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return nil, 0, nil, "doh", fmt.Errorf("DoH endpoint returned HTTP %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65536))
	if err != nil {
		return nil, 0, nil, "doh", err
	}
	msg := new(dns.Msg)
	if err := msg.Unpack(body); err != nil {
		return nil, 0, nil, "doh", fmt.Errorf("decode DoH response: %w", err)
	}
	if msg.Id != request.Id {
		return nil, 0, nil, "doh", errors.New("DoH response message ID does not match query")
	}
	return msg, time.Since(start), body, "doh", nil
}

func normalizeServer(input, transport string) (address, tlsName string, err error) {
	input = strings.TrimSpace(input)
	if transport == "doh" || transport == "https" {
		if input == "" {
			return "", "", errors.New("DoH requires --server with an https:// DNS-query endpoint")
		}
		u, parseErr := url.Parse(input)
		if parseErr != nil || u.Scheme != "https" || u.Host == "" {
			return "", "", fmt.Errorf("invalid DoH endpoint %q; an https:// URL is required", input)
		}
		return u.String(), u.Hostname(), nil
	}
	if input == "" {
		if transport == "dot" || transport == "tls" || transport == "tcp-tls" {
			return "", "", errors.New("DoT requires --server HOST[:PORT] so its TLS certificate can be verified")
		}
		input, err = DefaultResolver()
		if err != nil {
			return "", "", err
		}
	}
	host, port, splitErr := net.SplitHostPort(input)
	if splitErr != nil {
		host = strings.Trim(input, "[]")
		port = "53"
		if transport == "dot" || transport == "tls" || transport == "tcp-tls" {
			port = "853"
		}
	}
	if host == "" {
		return "", "", fmt.Errorf("invalid DNS server %q", input)
	}
	return net.JoinHostPort(host, port), host, nil
}

func buildResult(msg *dns.Msg, opts QueryOptions, server, transport string, queryWire, responseWire []byte, rtt time.Duration, fromCache bool, key string, expires *time.Time) *Result {
	result := &Result{
		Question: Question{Name: opts.Name, Type: opts.Type, Class: "IN"},
		Server:   server, Transport: transport, Timestamp: time.Now(), DurationMS: float64(rtt.Microseconds()) / 1000,
		FromCache: fromCache, CacheKey: key, CacheExpires: expires,
		MessageID: msg.Id, Rcode: rcodeString(msg.Rcode), RcodeNumber: msg.Rcode,
		Flags: flagsFromMessage(msg), Records: recordsFromMessage(msg), EDNS: ednsFromMessage(msg),
		DNSSEC:       dnssecFromMessage(msg, opts.DNSSEC),
		Wire:         WireInfo{QueryBytes: len(queryWire), ResponseBytes: len(responseWire), QueryHex: hex.Dump(queryWire), ResponseHex: hex.Dump(responseWire)},
		Explanations: responseExplanations(msg, transport, fromCache),
	}
	if msg.AuthenticatedData && !isEncrypted(transport) {
		result.Warnings = append(result.Warnings, "AD is an assertion by the resolver, not self-authenticating proof. On an untrusted network, use a trusted local validating resolver, DoT, or DoH.")
	}
	if suspiciousAdditional(msg) {
		result.Warnings = append(result.Warnings, "The Additional section contains an address that is unrelated or outside the delegated bailiwick. Treat it only as an untrusted hint; never cache it as authoritative data.")
	}
	return result
}

func cacheKey(opts QueryOptions, name, qtype, server, transport string) string {
	return fmt.Sprintf("%s|%s|%s|%s|do=%t|rd=%t|cd=%t|edns=%d", name, qtype, strings.ToLower(server), transport, opts.DNSSEC, opts.RecursionDesired, opts.CheckingDisabled, opts.EDNSSize)
}

func messageTTL(msg *dns.Msg) uint32 {
	var ttl uint32
	set := func(value uint32) {
		if value > 0 && (ttl == 0 || value < ttl) {
			ttl = value
		}
	}
	if len(msg.Answer) > 0 {
		for _, rr := range msg.Answer {
			set(rr.Header().Ttl)
		}
		return ttl
	}
	for _, rr := range msg.Ns {
		if soa, ok := rr.(*dns.SOA); ok {
			set(soa.Hdr.Ttl)
			set(soa.Minttl)
		}
	}
	return ttl
}

func ageTTLs(msg *dns.Msg, remaining time.Duration) {
	seconds := uint32(0)
	if remaining > 0 {
		seconds = uint32(remaining.Seconds())
	}
	for _, section := range [][]dns.RR{msg.Answer, msg.Ns, msg.Extra} {
		for _, rr := range section {
			if rr.Header().Rrtype != dns.TypeOPT && rr.Header().Ttl > seconds {
				rr.Header().Ttl = seconds
			}
		}
	}
}

func isEncrypted(transport string) bool {
	transport = strings.ToLower(transport)
	return strings.Contains(transport, "tls") || transport == "dot" || transport == "doh" || transport == "https"
}

func suspiciousAdditional(msg *dns.Msg) bool {
	referenced := make(map[string]bool)
	delegatedZone := ""
	for _, rr := range msg.Ns {
		if ns, ok := rr.(*dns.NS); ok {
			if delegatedZone == "" {
				delegatedZone = strings.ToLower(ns.Hdr.Name)
			}
			referenced[strings.ToLower(ns.Ns)] = true
		}
	}
	if delegatedZone == "" {
		for _, rr := range msg.Answer {
			switch value := rr.(type) {
			case *dns.MX:
				referenced[strings.ToLower(value.Mx)] = true
			case *dns.NS:
				referenced[strings.ToLower(value.Ns)] = true
			case *dns.SRV:
				referenced[strings.ToLower(value.Target)] = true
			case *dns.CNAME:
				referenced[strings.ToLower(value.Target)] = true
			}
		}
	}
	questionName := ""
	if len(msg.Question) > 0 {
		questionName = strings.ToLower(msg.Question[0].Name)
	}
	for _, rr := range msg.Extra {
		if rr.Header().Rrtype != dns.TypeA && rr.Header().Rrtype != dns.TypeAAAA {
			continue
		}
		owner := strings.ToLower(rr.Header().Name)
		if delegatedZone != "" {
			if !referenced[owner] || !dns.IsSubDomain(delegatedZone, owner) {
				return true
			}
			continue
		}
		if !referenced[owner] && (questionName == "" || !dns.IsSubDomain(questionName, owner)) {
			return true
		}
	}
	return false
}

func ReverseName(ip string) (string, error) {
	if net.ParseIP(strings.TrimSpace(ip)) == nil {
		return "", fmt.Errorf("%q is not an IPv4 or IPv6 address", ip)
	}
	return dns.ReverseAddr(ip)
}

func CachePathFromEnvironment() string {
	if value := strings.TrimSpace(os.Getenv("WHEREDNS_CACHE")); value != "" {
		return value
	}
	return DefaultCachePath()
}
