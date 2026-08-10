package learn

import (
	"sort"
	"strings"
)

type Topic struct {
	ID       string   `json:"id"`
	Title    string   `json:"title"`
	Summary  string   `json:"summary"`
	Concepts []string `json:"concepts"`
	Try      []string `json:"try"`
}

type Attack struct {
	ID            string     `json:"id"`
	Name          string     `json:"name"`
	Category      string     `json:"category"`
	Risk          string     `json:"risk"`
	Summary       string     `json:"summary"`
	Mechanism     []string   `json:"mechanism"`
	Prerequisites []string   `json:"prerequisites"`
	Signals       []string   `json:"signals"`
	Defenses      []string   `json:"defenses"`
	LabScenario   string     `json:"lab_scenario,omitempty"`
	Ethics        string     `json:"ethics"`
	Flow          AttackFlow `json:"flow"`
}

// AttackFlow is a safe, explanatory sequence diagram. It describes actors and
// messages conceptually; it is not an executable attack recipe.
type AttackFlow struct {
	Title   string      `json:"title"`
	Caption string      `json:"caption"`
	Actors  []FlowActor `json:"actors"`
	Events  []FlowEvent `json:"events"`
}

type FlowActor struct {
	ID    string `json:"id"`
	Label string `json:"label"`
	Role  string `json:"role"`
	Kind  string `json:"kind"`
}

type FlowEvent struct {
	From   string `json:"from"`
	To     string `json:"to"`
	Label  string `json:"label"`
	Detail string `json:"detail"`
	Kind   string `json:"kind"`
}

var topics = []Topic{
	{
		ID: "resolution", Title: "Recursive and iterative resolution",
		Summary:  "A stub resolver normally asks one recursive resolver for a complete answer. That resolver walks referrals from the root through a TLD to an authoritative server and caches what it learns.",
		Concepts: []string{"Stub resolver", "Recursive resolver", "Root hints", "Referral", "Authoritative server", "Glue record", "Bailiwick"},
		Try:      []string{"wheredns query example.com --type A", "wheredns trace example.com --type A"},
	},
	{
		ID: "records", Title: "Resource records and sections",
		Summary:  "DNS answers are typed RRsets. The Answer section addresses the question, Authority supplies delegation or negative proof, and Additional can carry useful but carefully scoped glue.",
		Concepts: []string{"RRset", "Owner name", "Type", "Class", "TTL", "RDATA", "Answer/Authority/Additional"},
		Try:      []string{"wheredns query example.com --type MX", "wheredns query example.com --type SOA", "wheredns types"},
	},
	{
		ID: "cache", Title: "Caching, TTLs, and negative caching",
		Summary:  "Resolvers reuse data until its TTL expires. NXDOMAIN and NODATA can also be cached using the SOA values. Cache keys must include the name, type, class, and relevant query context.",
		Concepts: []string{"TTL countdown", "Positive cache", "Negative cache", "SOA MINIMUM", "Cache hit", "Cache poisoning"},
		Try:      []string{"wheredns query example.com", "wheredns query example.com", "wheredns cache list", "wheredns query --no-cache example.com"},
	},
	{
		ID: "dnssec", Title: "DNSSEC chain of trust",
		Summary:  "DNSSEC signs RRsets. A validator begins with the root trust anchor, verifies parent DS to child DNSKEY links, then verifies RRSIGs and authenticated denial records such as NSEC or NSEC3.",
		Concepts: []string{"Trust anchor", "KSK/ZSK", "DNSKEY", "DS", "RRSIG", "NSEC/NSEC3", "AD/CD/DO bits", "Bogus vs insecure"},
		Try:      []string{"wheredns query cloudflare.com --type DNSKEY --dnssec", "wheredns trace cloudflare.com --type A --dnssec"},
	},
	{
		ID: "transport", Title: "UDP, TCP, DoT, and DoH",
		Summary:  "Classic DNS commonly starts over UDP and retries truncated responses over TCP. DoT and DoH authenticate and encrypt the client-to-resolver hop, but do not replace DNSSEC's data-origin authentication.",
		Concepts: []string{"UDP/53", "TCP/53", "TC flag", "DoT/853", "DoH/HTTPS", "Confidentiality", "Resolver trust"},
		Try:      []string{"wheredns query example.com --transport tcp", "wheredns query example.com --transport doh --server https://dns.google/dns-query"},
	},
	{
		ID: "edns", Title: "EDNS extensions",
		Summary:  "EDNS adds an OPT pseudo-record, larger UDP payload negotiation, DNSSEC's DO bit, cookies, client subnet, padding, and Extended DNS Errors without replacing the DNS header.",
		Concepts: []string{"OPT", "UDP payload size", "DO bit", "EDNS version", "ECS privacy", "Cookies", "EDE"},
		Try:      []string{"wheredns query example.com --edns-size 1232 --wire"},
	},
	{
		ID: "zones", Title: "Zones, delegation, and administration",
		Summary:  "The namespace is divided into zones. NS and DS records cross delegation boundaries; SOA describes a zone; AXFR/IXFR, NOTIFY, dynamic update, TSIG, and SIG(0) support administration.",
		Concepts: []string{"Zone cut", "Delegation", "Glue", "SOA serial", "AXFR/IXFR", "NOTIFY", "RFC 2136 update", "TSIG"},
		Try:      []string{"wheredns query example.com --type NS", "wheredns query example.com --type SOA"},
	},
}

var attacks = []Attack{
	attack("cache-poisoning", "Cache poisoning and Kaminsky-style forgery", "Integrity", "critical",
		"A resolver accepts a forged response and caches attacker-chosen data, redirecting later clients.",
		[]string{"An attacker races the legitimate reply with guessed transaction IDs and source ports.", "Classic Kaminsky attacks force many cache misses using random subdomains and inject a forged delegation.", "Weak bailiwick rules can cause unrelated Additional-section data to be cached."},
		[]string{"Ability to send spoofed packets toward a recursive resolver", "Predictable or insufficient query entropy", "A cache miss and weak validation"},
		[]string{"Sudden NS/address changes", "Out-of-bailiwick glue", "Very short-lived bursts of random subdomain queries", "Answers inconsistent across trusted resolvers"},
		[]string{"DNSSEC validation", "Strong transaction/source-port entropy", "Strict question and bailiwick checks", "DNS cookies where supported", "Hardened current resolver software"}, "cache-poisoning"),
	attack("on-path-spoofing", "On-path DNS spoofing", "Integrity / surveillance", "high",
		"A network observer races or replaces plaintext DNS replies between a client and resolver.",
		[]string{"Observe the UDP query", "Return a matching forged response before the real server", "Optionally suppress the legitimate response"},
		[]string{"Position on the network path or control of a gateway", "Unencrypted DNS and no effective DNSSEC validation"},
		[]string{"Answers change by network", "Invalid DNSSEC responses", "Unexpected low TTLs or private IPs"},
		[]string{"DoT/DoH to an authenticated resolver", "Local DNSSEC validation", "Secure network access and gateway controls"}, "cache-poisoning"),
	attack("dns-hijacking", "Resolver, router, and registrar hijacking", "Control plane", "critical",
		"An attacker changes resolver settings, authoritative delegation, or zone records rather than forging individual packets.",
		[]string{"Compromise a router/DHCP service, registrar, DNS provider, or administrative credential", "Point clients or the parent zone toward attacker-controlled infrastructure"},
		[]string{"Administrative access, credential theft, provider compromise, or malicious network provisioning"},
		[]string{"Nameserver changes", "Unexpected DNS settings from DHCP", "Registry alerts", "Certificate transparency anomalies"},
		[]string{"Registrar lock and MFA", "Least privilege", "DNS change monitoring", "DNSSEC with protected DS management", "Harden DHCP and routers"}, ""),
	attack("amplification", "Reflection and amplification DDoS", "Availability", "critical",
		"Open resolvers or authoritative servers send responses much larger than spoofed requests to a victim.",
		[]string{"Spoof the victim's source IP", "Send queries with a high response-to-request ratio", "Many reflectors converge traffic on the victim"},
		[]string{"Networks permitting source-address spoofing", "Open recursive resolvers or amplifiable authoritative answers"},
		[]string{"High-rate UDP/53 responses without matching requests", "ANY/DNSSEC-heavy query patterns", "Many disparate reflectors"},
		[]string{"BCP 38 source validation", "Disable open recursion", "Response-rate limiting", "Minimal ANY responses", "Anycast and DDoS protection"}, "amplification"),
	attack("dns-tunneling", "DNS tunneling and covert channels", "Exfiltration / command and control", "high",
		"Data is encoded into query labels or responses so DNS becomes a covert channel through restrictive networks.",
		[]string{"Encode chunks in long or high-entropy subdomains", "Use an attacker-controlled authoritative zone", "Return commands in TXT, CNAME, or other responses"},
		[]string{"Ability to make DNS queries", "Control of or access to an authoritative domain"},
		[]string{"Long/high-entropy labels", "Many unique subdomains", "Unusual TXT volume", "Regular beacon timing", "High NXDOMAIN ratio"},
		[]string{"Egress through managed resolvers only", "Entropy and behavioral monitoring", "Response policy", "Endpoint investigation", "Allowlist sensitive environments"}, "tunneling"),
	attack("rebinding", "DNS rebinding", "Browser boundary", "high",
		"A hostile domain changes from a public address to a private/loopback address, making a victim browser send same-origin requests toward an internal service.",
		[]string{"Serve a low-TTL public address", "Cause browser JavaScript to retain the origin", "Re-answer with an internal address"},
		[]string{"Victim visits attacker content", "Internal service relies on network location and accepts the Host/origin"},
		[]string{"Public names resolving to private ranges", "Rapid address changes", "Unexpected Host headers on internal services"},
		[]string{"Validate Host and Origin", "Authentication on internal services", "Resolver rebinding protection", "Block public-zone answers containing private addresses where appropriate"}, "rebinding"),
	attack("subdomain-takeover", "Dangling DNS and subdomain takeover", "Cloud configuration", "high",
		"A DNS record points to a deprovisioned third-party resource that another tenant can claim.",
		[]string{"Find a CNAME or address targeting an unclaimed SaaS/cloud resource", "Register the missing resource at that provider", "Serve content under the victim subdomain"},
		[]string{"Dangling record", "Provider permits resource-name reuse", "No ownership revalidation"},
		[]string{"Provider-specific unclaimed-resource errors", "CNAMEs to retired services", "Asset inventory drift"},
		[]string{"Delete DNS before deprovisioning", "Continuous dangling-record scans", "Provider ownership verification", "Controlled lifecycle automation"}, ""),
	attack("zone-transfer", "Unauthorized zone transfer", "Information disclosure", "medium",
		"A misconfigured authoritative server allows AXFR/IXFR to an unauthorized client, revealing hostnames and topology.",
		[]string{"Request an AXFR over TCP", "Server returns the zone between opening and closing SOA records"},
		[]string{"Authoritative server with overly broad transfer ACL"},
		[]string{"Successful transfers from unknown clients", "AXFR requests at the perimeter"},
		[]string{"Restrict transfers to known secondaries", "Authenticate with TSIG", "Monitor transfer logs", "Avoid treating hidden names as a security boundary"}, "zone-transfer"),
	attack("dynamic-update", "Unauthorized dynamic DNS update", "Integrity", "critical",
		"A server accepts RFC 2136 updates from an unauthorized party, allowing records to be created, replaced, or deleted.",
		[]string{"Send an UPDATE message satisfying weak or absent policy", "Alter an RRset or delegation"},
		[]string{"Exposed update service and missing/weak authentication"},
		[]string{"Unexpected UPDATE opcodes", "Zone journal changes", "New records with anomalous owners or TTLs"},
		[]string{"TSIG or SIG(0)", "Narrow update policies", "Network ACLs", "Audit and alert on zone changes"}, ""),
	attack("dnssec-failure", "DNSSEC downgrade and misconfiguration", "Authenticity", "high",
		"Broken signatures, expired keys, missing DS changes, or clients that silently fall back can turn protection into outage or insecurity.",
		[]string{"Serve invalid/expired signatures or break the DS-to-DNSKEY link", "Exploit applications that treat bogus DNSSEC as merely unsigned"},
		[]string{"Operational key/clock/delegation error or an application with incorrect fallback"},
		[]string{"SERVFAIL only from validating resolvers", "RRSIG time errors", "DS/DNSKEY mismatch"},
		[]string{"Automated rollover monitoring", "Clock synchronization", "Multi-vantage validation", "Fail closed for bogus data while allowing genuinely insecure delegations"}, "dnssec-bogus"),
	attack("sad-dns", "SAD DNS side-channel poisoning", "Integrity", "high",
		"ICMP rate-limit side channels can help infer a resolver's UDP source port, reducing entropy needed for forged responses.",
		[]string{"Probe closed UDP ports indirectly", "Infer the live DNS source port from ICMP behavior", "Race transaction IDs with forged replies"},
		[]string{"Spoofing capability", "Vulnerable network stack/rate-limit behavior", "Accessible recursive resolver"},
		[]string{"Abnormal ICMP/UDP probing around DNS traffic", "Unexplained cache changes"},
		[]string{"Patched kernels/resolvers", "DNS cookies", "DNSSEC validation", "Restrict resolver access and source spoofing"}, ""),
	attack("fragmentation", "IP-fragment DNS poisoning", "Integrity / availability", "high",
		"Large UDP responses fragment; an attacker forges a later fragment that is reassembled with a legitimate first fragment.",
		[]string{"Predict fragment identifiers and matching tuple", "Replace a non-initial fragment carrying answer data"},
		[]string{"Fragmented UDP DNS path and injection capability"},
		[]string{"Overlapping/incomplete fragments", "Large DNSSEC UDP answers", "Checksum or reassembly anomalies"},
		[]string{"EDNS size near 1232", "TCP fallback", "DNSSEC validation", "Fragment filtering/reassembly hardening"}, ""),
	attack("random-subdomain", "Random-subdomain / water-torture attack", "Availability", "high",
		"Attackers ask recursive resolvers for endless unique names, bypassing caches and overloading authoritative servers.",
		[]string{"Generate random labels under a target zone", "Distribute requests through many clients/resolvers", "Force repeated authoritative lookups"},
		[]string{"Query-generation capacity", "Target zone with finite authoritative capacity"},
		[]string{"High unique-name and NXDOMAIN rate", "Low cache-hit ratio", "Stable parent zone with random leftmost labels"},
		[]string{"Rate limiting and aggressive negative caching", "Anycast capacity", "Resolver anomaly detection", "Upstream DDoS coordination"}, ""),
	attack("nxnsattack", "NXNSAttack referral fan-out", "Availability", "high",
		"A malicious delegation names many unreachable name servers, causing recursive resolvers to issue a large fan-out of address and retry queries.",
		[]string{"Return referrals containing many NS names without glue", "Resolver tries to resolve and contact each target"},
		[]string{"Attacker-controlled authoritative zone", "Resolver without strict fetch/retry limits"},
		[]string{"Explosive NS-address lookups", "Many failures following one referral"},
		[]string{"Current resolver software", "Limits on referral NS processing, retries, and concurrent fetches", "Response-rate controls"}, ""),
	attack("ghost-domain", "Ghost-domain persistence", "Abuse persistence", "medium",
		"Carefully refreshed delegations can remain in resolver caches after a domain is removed or its delegation changes.",
		[]string{"Use long TTLs and repeatedly refresh cached delegation state", "Continue serving through stale infrastructure"},
		[]string{"Resolver cache behavior that permits stale delegation refresh", "Prior control of the domain"},
		[]string{"Answers persist beyond registry removal", "Stale NS data across resolvers"},
		[]string{"Resolver patches and delegation revalidation", "TTL caps where appropriate", "Registry/resolver coordination"}, ""),
	attack("fast-flux", "Fast flux and domain generation", "Evasion", "medium",
		"Malware rapidly changes many addresses or generates many candidate domains to make infrastructure harder to block.",
		[]string{"Rotate large address pools behind low TTLs", "Use a domain-generation algorithm for rendezvous"},
		[]string{"Control of domains and distributed hosts"},
		[]string{"Rapidly changing RRsets", "Low TTLs", "High ASN/geographic diversity", "Many algorithmic NXDOMAINs"},
		[]string{"Passive-DNS and behavioral detection", "Sinkholing with authorization", "Registrar/provider coordination", "Endpoint remediation"}, ""),
	attack("homograph", "IDN homograph and typosquatting", "Social engineering", "high",
		"Lookalike Unicode or misspelled domains deceive users even though DNS itself resolves correctly.",
		[]string{"Register a visually similar name", "Use links, email, or ads to draw victims", "Obtain ordinary TLS for the lookalike domain"},
		[]string{"Confusable available domain and a delivery channel"},
		[]string{"Punycode labels", "Newly registered lookalikes", "Brand-adjacent certificate issuance"},
		[]string{"Display registrable domains clearly", "Email/web filtering", "Defensive registration", "Certificate transparency and domain monitoring", "User verification habits"}, ""),
	attack("doh-abuse", "Encrypted DNS policy bypass", "Evasion / privacy", "medium",
		"Malware or unmanaged applications use external DoH/DoT endpoints to evade local DNS filtering and visibility.",
		[]string{"Send encrypted DNS to an allowed HTTPS endpoint", "Resolve command-and-control names outside the managed resolver"},
		[]string{"Outbound access to unmanaged encrypted resolvers"},
		[]string{"Known DoH endpoint traffic from unexpected processes", "DNS-like request cadence over HTTPS"},
		[]string{"Managed encrypted DNS", "Endpoint controls", "Network policy for external resolvers", "Preserve privacy while logging only necessary security metadata"}, ""),
	attack("lame-delegation", "Lame delegation and cyclic dependency", "Availability / configuration", "medium",
		"Delegated name servers are non-authoritative, unreachable, or depend circularly on names that cannot be resolved.",
		[]string{"Parent publishes unusable NS set", "Resolvers retry across broken targets until timeout"},
		[]string{"Configuration error or compromised delegation management"},
		[]string{"REFUSED/SERVFAIL from delegated servers", "Missing glue", "Repeated timeouts", "Parent/child NS mismatch"},
		[]string{"Continuous delegation checks", "Diverse authoritative servers", "Correct in-bailiwick glue", "Coordinated parent/child changes"}, "lame-delegation"),
}

func attack(id, name, category, risk, summary string, mechanism, prereq, signals, defenses []string, lab string) Attack {
	return Attack{ID: id, Name: name, Category: category, Risk: risk, Summary: summary, Mechanism: mechanism, Prerequisites: prereq, Signals: signals, Defenses: defenses, LabScenario: lab, Ethics: "Use only the included isolated simulation or systems you own and are explicitly authorized to test."}
}

func Topics() []Topic {
	out := append([]Topic(nil), topics...)
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out
}

func TopicByID(id string) (Topic, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, topic := range topics {
		if topic.ID == id {
			return topic, true
		}
	}
	return Topic{}, false
}

func Attacks() []Attack {
	out := append([]Attack(nil), attacks...)
	for i := range out {
		out[i].Flow = attackFlows[out[i].ID]
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func AttackByID(id string) (Attack, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, attack := range attacks {
		if attack.ID == id {
			attack.Flow = attackFlows[attack.ID]
			return attack, true
		}
	}
	return Attack{}, false
}
