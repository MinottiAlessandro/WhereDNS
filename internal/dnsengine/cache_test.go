package dnsengine

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
)

func TestCacheExpiresEntries(t *testing.T) {
	cache, err := NewCache("")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	cache.now = func() time.Time { return now }
	if err := cache.Put("key", "example.test.", "A", "127.0.0.1:53", []byte{1, 2, 3}, 10); err != nil {
		t.Fatal(err)
	}
	if _, _, hit, err := cache.Get("key"); err != nil || !hit {
		t.Fatalf("expected cache hit, hit=%t err=%v", hit, err)
	}
	now = now.Add(11 * time.Second)
	if _, _, hit, err := cache.Get("key"); err != nil || hit {
		t.Fatalf("expected expired miss, hit=%t err=%v", hit, err)
	}
}

func TestNegativeTTLUsesSOA(t *testing.T) {
	msg := new(dns.Msg)
	msg.Rcode = dns.RcodeNameError
	msg.Ns = append(msg.Ns, &dns.SOA{Hdr: dns.RR_Header{Name: "test.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300}, Minttl: 60})
	if got := messageTTL(msg); got != 60 {
		t.Fatalf("messageTTL=%d, want 60", got)
	}
}

func TestEngineQueriesAndReusesExplicitCache(t *testing.T) {
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var requests atomic.Int32
	server := &dns.Server{PacketConn: packet, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, request *dns.Msg) {
		requests.Add(1)
		response := new(dns.Msg)
		response.SetReply(request)
		response.Authoritative = true
		rr, _ := dns.NewRR("learn.test. 60 IN A 192.0.2.10")
		response.Answer = []dns.RR{rr}
		_ = w.WriteMsg(response)
	})}
	go func() { _ = server.ActivateAndServe() }()
	t.Cleanup(func() { _ = server.Shutdown() })

	cache, _ := NewCache("")
	engine := New(cache)
	options := DefaultOptions("learn.test")
	options.Server = packet.LocalAddr().String()
	options.DNSSEC = false
	first, err := engine.Query(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	second, err := engine.Query(context.Background(), options)
	if err != nil {
		t.Fatal(err)
	}
	if first.FromCache || !second.FromCache {
		t.Fatalf("unexpected cache flags: first=%t second=%t", first.FromCache, second.FromCache)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("server received %d requests, want 1", got)
	}
	if len(second.Records) == 0 || second.Records[0].Data != "192.0.2.10" {
		t.Fatalf("unexpected cached records: %#v", second.Records)
	}
}

func TestNormalizeInternationalizedName(t *testing.T) {
	got, err := NormalizeName("BÜCHER.example")
	if err != nil {
		t.Fatal(err)
	}
	if got != "xn--bcher-kva.example." {
		t.Fatalf("NormalizeName=%q", got)
	}
}
