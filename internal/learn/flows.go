package learn

// attackFlows supplies structured, defensive diagrams for every atlas entry.
// The events emphasize trust boundaries, observable effects, and controls.
var attackFlows = map[string]AttackFlow{
	"cache-poisoning": flow(
		"Forged data races a legitimate answer",
		"The resolver should accept only a response that matches its outstanding query, passes bailiwick checks, and validates when DNSSEC is expected.",
		[]FlowActor{
			actor("client", "DNS client", "asks for a name", "user"),
			actor("resolver", "Recursive resolver", "holds outstanding query state", "resolver"),
			actor("attacker", "Off-path attacker", "guesses response tuple", "attacker"),
			actor("authority", "Authoritative DNS", "returns legitimate data", "infrastructure"),
			actor("cache", "Resolver cache", "serves later clients", "cache"),
		},
		[]FlowEvent{
			event("client", "resolver", "Cache-miss query", "A random subdomain can force a fresh upstream lookup.", "normal"),
			event("resolver", "authority", "Iterative query", "The resolver records the server, ports, transaction ID, name, class, and type it expects.", "normal"),
			event("attacker", "resolver", "Forged referral race", "Blind guesses try to arrive before the authoritative response. Unrelated Additional data is outside the trust boundary.", "malicious"),
			event("authority", "resolver", "Legitimate response", "A matching answer returns through the normal delegation path.", "normal"),
			event("resolver", "cache", "Validate or reject", "Strict tuple matching, bailiwick rules, DNS cookies, and DNSSEC validation prevent forged data becoming durable cache state.", "defense"),
		},
	),
	"on-path-spoofing": flow(
		"A network observer alters plaintext DNS",
		"Encryption authenticates the client-to-resolver channel; DNSSEC validation independently authenticates signed DNS data.",
		[]FlowActor{
			actor("client", "DNS client", "originates the question", "user"),
			actor("onpath", "On-path attacker", "observes or changes packets", "attacker"),
			actor("resolver", "Recursive resolver", "answers the client", "resolver"),
			actor("validator", "Validation policy", "checks channel and data", "defense"),
		},
		[]FlowEvent{
			event("client", "resolver", "Plaintext UDP question", "Classic DNS exposes the question and its matching fields to devices on the path.", "warning"),
			event("onpath", "client", "Raced forged answer", "The attacker can inject a matching response and may suppress the legitimate packet.", "malicious"),
			event("resolver", "client", "Legitimate answer", "Without protection the client may accept whichever plausible response wins.", "normal"),
			event("validator", "client", "DoT/DoH + DNSSEC", "An authenticated encrypted resolver channel blocks path injection; DNSSEC detects forged signed data.", "defense"),
		},
	),
	"dns-hijacking": flow(
		"Control-plane changes redirect many queries",
		"Unlike a packet race, hijacking changes persistent configuration at a router, resolver, DNS provider, or registrar.",
		[]FlowActor{
			actor("attacker", "Account attacker", "targets administrative access", "attacker"),
			actor("control", "DNS control plane", "router, provider, or registrar", "infrastructure"),
			actor("rogue", "Rogue DNS service", "serves chosen answers", "attacker"),
			actor("client", "Affected clients", "follow changed configuration", "target"),
			actor("monitor", "Change monitoring", "detects unauthorized state", "defense"),
		},
		[]FlowEvent{
			event("attacker", "control", "Credential or admin compromise", "A privileged DNS setting, zone record, or delegation is modified.", "malicious"),
			event("control", "client", "Changed resolver/delegation", "DHCP, router, zone, or parent data now points clients toward attacker-controlled infrastructure.", "warning"),
			event("client", "rogue", "Queries follow new path", "The redirection persists without winning every individual DNS packet race.", "malicious"),
			event("monitor", "control", "Lock, MFA, and alert", "Registrar locks, least privilege, protected DS changes, and independent change monitoring reduce exposure and dwell time.", "defense"),
		},
	),
	"amplification": flow(
		"Small spoofed questions produce large reflected answers",
		"Reflection chooses the victim; amplification increases the bytes. The diagram is conceptual and the WhereDNS lab performs arithmetic only.",
		[]FlowActor{
			actor("attacker", "Spoofing source", "sends forged-source queries", "attacker"),
			actor("reflector", "Open resolver", "answers unauthenticated clients", "resolver"),
			actor("victim", "Victim", "receives unsolicited responses", "target"),
			actor("network", "Network controls", "filters spoofing and rate", "defense"),
		},
		[]FlowEvent{
			event("attacker", "reflector", "Small query; source = victim", "The UDP source address is forged where the source network does not apply ingress/egress validation.", "malicious"),
			event("reflector", "victim", "Larger DNS response", "The resolver reflects its answer to the apparent source. Many reflectors can converge on one victim.", "warning"),
			event("network", "attacker", "BCP 38 source validation", "Dropping packets with impossible source addresses removes the reflection primitive near its origin.", "defense"),
			event("network", "reflector", "Recursion ACL + response limits", "Closing open recursion, minimal ANY behavior, and response-rate limiting reduce abuse.", "defense"),
		},
	),
	"dns-tunneling": flow(
		"Application data is disguised as DNS labels and answers",
		"A suspicious label is a signal, not proof. Defenders correlate entropy, uniqueness, timing, query type, destination zone, and endpoint process.",
		[]FlowActor{
			actor("endpoint", "Compromised endpoint", "encodes data in queries", "attacker"),
			actor("resolver", "Managed resolver", "forwards allowed DNS", "resolver"),
			actor("authority", "Attacker authority", "decodes data and replies", "attacker"),
			actor("analyst", "Security analyst", "correlates DNS and process", "defense"),
		},
		[]FlowEvent{
			event("endpoint", "resolver", "High-entropy subdomain", "Encoded chunks appear as long, frequently unique labels under one zone.", "malicious"),
			event("resolver", "authority", "Normal DNS forwarding", "The protocol-valid request can cross networks that permit DNS while restricting other egress.", "warning"),
			event("authority", "endpoint", "TXT/CNAME command data", "Responses can carry small command or acknowledgement payloads.", "malicious"),
			event("analyst", "endpoint", "Correlated detection", "Managed resolver telemetry plus endpoint process context distinguishes covert behavior from CDNs and service discovery.", "defense"),
		},
	),
	"rebinding": flow(
		"One browser origin resolves to two network locations",
		"The hostname remains constant while a low-TTL answer changes from a public address to loopback or a private range.",
		[]FlowActor{
			actor("browser", "Victim browser", "retains scheme/host/port origin", "user"),
			actor("authority", "Hostile authority", "changes low-TTL answers", "attacker"),
			actor("public", "Public web host", "serves attacker script", "infrastructure"),
			actor("internal", "Internal service", "trusts network location", "target"),
			actor("guard", "Service + resolver guards", "validate destination and origin", "defense"),
		},
		[]FlowEvent{
			event("authority", "browser", "First answer: public IP", "The browser loads content for the hostile hostname from a public address with a short TTL.", "normal"),
			event("public", "browser", "Script keeps same origin", "The URL hostname is unchanged even after the DNS TTL expires.", "malicious"),
			event("authority", "browser", "Second answer: private IP", "A later lookup maps the same hostname to loopback or an internal address.", "malicious"),
			event("browser", "internal", "Same-host request", "The browser may direct the request at an internal service that wrongly trusts network location alone.", "warning"),
			event("guard", "internal", "Authenticate + validate Host/Origin", "Service authentication, request validation, browser protections, and resolver rebinding filters break the path.", "defense"),
		},
	),
	"subdomain-takeover": flow(
		"A dangling DNS target is claimed by another tenant",
		"The DNS record is still controlled by the victim, but its deprovisioned third-party destination can be re-registered.",
		[]FlowActor{
			actor("victimdns", "Victim DNS zone", "publishes stale CNAME", "infrastructure"),
			actor("provider", "Cloud/SaaS provider", "resource was deleted", "infrastructure"),
			actor("attacker", "New tenant", "claims reusable resource", "attacker"),
			actor("visitor", "Site visitor", "trusts victim subdomain", "target"),
			actor("lifecycle", "Asset lifecycle", "removes DNS first", "defense"),
		},
		[]FlowEvent{
			event("victimdns", "provider", "Dangling CNAME", "The DNS record outlives the third-party resource it names.", "warning"),
			event("attacker", "provider", "Claim missing resource", "If the provider permits name reuse without ownership revalidation, another tenant can bind the target.", "malicious"),
			event("visitor", "victimdns", "Resolve trusted subdomain", "DNS follows the unchanged CNAME toward content now controlled by the attacker.", "malicious"),
			event("lifecycle", "victimdns", "Delete DNS before service", "Coordinated deprovisioning and continuous dangling-record checks close the window.", "defense"),
		},
	),
	"zone-transfer": flow(
		"An authorization failure exposes a zone inventory",
		"AXFR is legitimate secondary replication over TCP. The security issue is an authoritative server returning it to an unauthorized client.",
		[]FlowActor{
			actor("requester", "Unauthorized client", "requests complete zone", "attacker"),
			actor("authority", "Authoritative server", "holds zone database", "infrastructure"),
			actor("inventory", "Zone inventory", "names and topology", "target"),
			actor("secondary", "Approved secondary", "legitimate transfer peer", "resolver"),
			actor("policy", "Transfer policy", "ACL + TSIG", "defense"),
		},
		[]FlowEvent{
			event("requester", "authority", "AXFR over TCP", "A complete transfer is requested for a zone apex.", "malicious"),
			event("authority", "inventory", "Opening SOA … closing SOA", "A permissive server serializes records that can reveal hostnames and topology.", "warning"),
			event("authority", "requester", "Zone contents disclosed", "The leak aids reconnaissance, although hidden names should never be the sole security boundary.", "malicious"),
			event("policy", "authority", "Authorize known secondaries", "Narrow ACLs, TSIG authentication, and transfer logging allow only intended replication.", "defense"),
			event("authority", "secondary", "Authenticated replication", "The same protocol remains available for its legitimate operational purpose.", "normal"),
		},
	),
	"dynamic-update": flow(
		"An unauthorized UPDATE mutates authoritative data",
		"RFC 2136 dynamic update is an administration protocol. Authentication and narrowly scoped update policy are its trust boundary.",
		[]FlowActor{
			actor("requester", "Unauthorized updater", "submits UPDATE message", "attacker"),
			actor("authority", "Primary DNS server", "evaluates update policy", "infrastructure"),
			actor("zone", "Zone database", "stores changed RRsets", "target"),
			actor("clients", "DNS clients", "receive altered data", "user"),
			actor("policy", "TSIG/SIG(0) policy", "authenticates narrow rights", "defense"),
		},
		[]FlowEvent{
			event("requester", "authority", "Create/replace/delete RRset", "A weak or absent update policy accepts a request from the wrong principal.", "malicious"),
			event("authority", "zone", "Journal and zone change", "The mutation becomes authoritative data rather than a transient forged packet.", "warning"),
			event("zone", "clients", "Altered DNS answers", "Clients follow the malicious record until it is removed and caches expire.", "malicious"),
			event("policy", "authority", "Authenticate + scope names/types", "TSIG or SIG(0), network ACLs, least privilege, and audit prevent or expose unauthorized changes.", "defense"),
		},
	),
	"dnssec-failure": flow(
		"A broken chain must fail as bogus, not downgrade",
		"A signed answer is useful only when DS, DNSKEY, and RRSIG links connect correctly to a trust anchor and are valid in time.",
		[]FlowActor{
			actor("parent", "Parent zone", "publishes child DS", "infrastructure"),
			actor("child", "Signed child zone", "publishes DNSKEY + RRSIG", "infrastructure"),
			actor("validator", "Validating resolver", "builds chain of trust", "resolver"),
			actor("client", "DNS client", "expects validated result", "user"),
			actor("operator", "DNS operator", "monitors rollover state", "defense"),
		},
		[]FlowEvent{
			event("parent", "validator", "DS identifies key K1", "An authenticated DS means the validator expects a matching child DNSKEY.", "normal"),
			event("child", "validator", "DNSKEY K2 + signatures", "A faulty rollover, expiration, clock error, or mismatched key breaks the expected chain.", "warning"),
			event("validator", "client", "SERVFAIL: bogus", "The safe result is failure; silently treating a broken signed delegation as unsigned creates a downgrade.", "defense"),
			event("operator", "child", "Repair and monitor rollover", "Automated DS/DNSKEY, signature-time, and multi-vantage checks prevent prolonged outages.", "defense"),
		},
	),
	"sad-dns": flow(
		"A side channel reduces source-port uncertainty",
		"SAD DNS combines source spoofing with ICMP rate-limit behavior. Patched systems and DNSSEC validation close separate layers of the attack.",
		[]FlowActor{
			actor("attacker", "Off-path attacker", "probes and forges", "attacker"),
			actor("network", "ICMP/network stack", "leaks rate-limit behavior", "infrastructure"),
			actor("resolver", "Recursive resolver", "has live UDP query port", "resolver"),
			actor("authority", "Authoritative DNS", "returns genuine response", "infrastructure"),
			actor("validator", "Patched validator", "removes side channel / verifies data", "defense"),
		},
		[]FlowEvent{
			event("resolver", "authority", "Outstanding UDP query", "The resolver chooses a randomized source port and transaction ID.", "normal"),
			event("attacker", "network", "Spoofed closed-port probes", "Shared ICMP rate-limit behavior can reveal which candidate port is in use on vulnerable systems.", "malicious"),
			event("network", "attacker", "Port side-channel signal", "Learning the port removes part of the entropy before the forged-response race.", "warning"),
			event("attacker", "resolver", "Reduced-space forgery race", "The attacker still needs spoofing and a matching transaction ID/question before a genuine reply wins.", "malicious"),
			event("validator", "resolver", "Kernel patch + DNSSEC", "Current network-stack behavior, access restrictions, cookies, and validation defend at distinct layers.", "defense"),
		},
	),
	"fragmentation": flow(
		"A forged later fragment corrupts a large UDP response",
		"Keeping DNS UDP payloads near 1,232 bytes and falling back to TCP reduces fragmentation; DNSSEC detects forged signed answer data.",
		[]FlowActor{
			actor("authority", "Authoritative DNS", "sends large UDP response", "infrastructure"),
			actor("network", "IP network", "fragments and reassembles", "infrastructure"),
			actor("attacker", "Injection attacker", "predicts fragment tuple", "attacker"),
			actor("resolver", "Recursive resolver", "accepts reassembled DNS", "resolver"),
			actor("guard", "Transport + validation", "avoids or rejects corruption", "defense"),
		},
		[]FlowEvent{
			event("authority", "network", "Large DNSSEC UDP answer", "A response exceeding the path MTU may be split into multiple IP fragments.", "warning"),
			event("attacker", "network", "Forged non-initial fragment", "An attacker who can predict the matching tuple attempts to replace answer-bearing bytes.", "malicious"),
			event("network", "resolver", "Reassembled response", "Weak reassembly conditions can combine a legitimate first fragment with attacker data.", "malicious"),
			event("guard", "resolver", "1,232-byte EDNS, TCP, DNSSEC", "Fragment avoidance, hardened reassembly, TCP fallback, and signature validation break different prerequisites.", "defense"),
		},
	),
	"random-subdomain": flow(
		"Unique names defeat caches and concentrate upstream work",
		"Also called water torture: many resolvers can convert distributed client queries into repeated authoritative lookups for one zone.",
		[]FlowActor{
			actor("bots", "Distributed clients", "generate random labels", "attacker"),
			actor("resolvers", "Recursive resolvers", "see cache misses", "resolver"),
			actor("authority", "Target authority", "answers every unique name", "target"),
			actor("defense", "Resolver + DDoS controls", "limit abusive work", "defense"),
		},
		[]FlowEvent{
			event("bots", "resolvers", "a8f…target.test, q2k…target.test", "Random leftmost labels make each request a different cache key.", "malicious"),
			event("resolvers", "authority", "Repeated cache-miss lookups", "Recursive resolvers perform fresh delegation and authoritative work instead of reusing an RRset.", "warning"),
			event("authority", "resolvers", "NXDOMAIN / wildcard answers", "Response work and bandwidth concentrate on the target authoritative service.", "malicious"),
			event("defense", "resolvers", "Aggressive negative cache + limits", "Behavioral rate limits, current resolver features, anycast capacity, and upstream coordination reduce load.", "defense"),
		},
	),
	"nxnsattack": flow(
		"One malicious referral fans out into many resolver fetches",
		"A recursive resolver needs addresses for referral NS names. Strict limits prevent a response from multiplying work without bound.",
		[]FlowActor{
			actor("client", "DNS client", "queries attacker-controlled zone", "user"),
			actor("resolver", "Recursive resolver", "follows referrals", "resolver"),
			actor("malicious", "Malicious authority", "returns oversized NS set", "attacker"),
			actor("targets", "Many NS targets", "unreachable or victim names", "target"),
			actor("limits", "Resolver work limits", "caps fetches and retries", "defense"),
		},
		[]FlowEvent{
			event("client", "resolver", "One ordinary question", "The initial query itself need not be large or unusual.", "normal"),
			event("resolver", "malicious", "Authoritative lookup", "Resolution reaches a zone controlled by the attacker.", "normal"),
			event("malicious", "resolver", "Referral: many NS, no glue", "The response induces address discovery for numerous name-server targets.", "malicious"),
			event("resolver", "targets", "Address fetch and retry fan-out", "An unbounded resolver creates many secondary queries and connection attempts.", "warning"),
			event("limits", "resolver", "Cap NS, concurrency, and retry", "Current resolver software constrains induced work per client query.", "defense"),
		},
	),
	"ghost-domain": flow(
		"Stale delegation data outlives registry removal",
		"Resolver patches and delegation revalidation prevent cached authority from refreshing itself indefinitely.",
		[]FlowActor{
			actor("registry", "Parent/registry", "removes delegation", "infrastructure"),
			actor("cache", "Recursive cache", "holds long-lived NS data", "cache"),
			actor("ghost", "Former authority", "keeps answering", "attacker"),
			actor("client", "DNS client", "queries removed domain", "target"),
			actor("guard", "Revalidation policy", "checks parent state", "defense"),
		},
		[]FlowEvent{
			event("registry", "cache", "Delegation removed upstream", "The parent no longer intends the former child servers to be authoritative.", "normal"),
			event("client", "cache", "Query finds cached NS", "Long TTLs or vulnerable refresh behavior can preserve older delegation state.", "warning"),
			event("cache", "ghost", "Refresh stale delegation", "The resolver contacts former infrastructure and may refresh data without confirming the parent.", "malicious"),
			event("ghost", "client", "Domain appears to persist", "Answers remain visible at affected resolvers after removal or delegation change.", "warning"),
			event("guard", "cache", "Revalidate at parent", "Patched cache rules, TTL controls, and registry/resolver coordination terminate stale authority.", "defense"),
		},
	),
	"fast-flux": flow(
		"Low-TTL address pools and generated names resist blocking",
		"Rapid change is not malicious by itself. Passive-DNS history, ownership, infrastructure diversity, and endpoint behavior provide context.",
		[]FlowActor{
			actor("endpoint", "Infected endpoint", "looks up rendezvous names", "target"),
			actor("resolver", "Recursive resolver", "returns changing RRsets", "resolver"),
			actor("fluxdns", "Flux DNS authority", "rotates low-TTL addresses", "attacker"),
			actor("proxies", "Distributed proxy hosts", "front malicious service", "attacker"),
			actor("analyst", "Threat analyst", "correlates behavior", "defense"),
		},
		[]FlowEvent{
			event("endpoint", "resolver", "DGA or low-TTL name query", "Malware may generate candidate domains until one is registered and active.", "malicious"),
			event("resolver", "fluxdns", "Cache expires frequently", "Short TTLs cause repeated authoritative lookups and rapidly changing address sets.", "warning"),
			event("fluxdns", "endpoint", "Rotating IP RRset", "Returned addresses span many networks or regions and point toward transient front-end hosts.", "malicious"),
			event("endpoint", "proxies", "Connect to current proxy", "The backend remains obscured behind replaceable hosts.", "malicious"),
			event("analyst", "endpoint", "Passive DNS + endpoint response", "Historical RRsets, ASN diversity, DGA patterns, and process telemetry support detection and remediation.", "defense"),
		},
	),
	"homograph": flow(
		"A lookalike name resolves correctly but deceives the user",
		"This is social engineering around DNS, not a forged DNS answer. TLS can be valid for the attacker's distinct domain.",
		[]FlowActor{
			actor("attacker", "Lookalike registrant", "registers confusable name", "attacker"),
			actor("delivery", "Email/ad/link", "presents deceptive text", "attacker"),
			actor("user", "User", "reads visual hostname", "target"),
			actor("dns", "DNS + TLS", "correctly serve distinct name", "infrastructure"),
			actor("guard", "Display + monitoring", "exposes registrable domain", "defense"),
		},
		[]FlowEvent{
			event("attacker", "delivery", "Unicode or typo lookalike", "A visually confusable or misspelled domain is registered and placed in a lure.", "malicious"),
			event("delivery", "user", "Trusted-looking link", "The user may perceive a familiar brand even though the code points and registrable domain differ.", "malicious"),
			event("user", "dns", "Ordinary lookup and HTTPS", "DNS resolves the attacker's real name and an ordinary certificate can be issued for that distinct name.", "warning"),
			event("guard", "user", "Punycode/registrable-domain context", "Clear hostname display, filtering, lookalike registration and certificate monitoring help users and defenders identify deception.", "defense"),
		},
	),
	"doh-abuse": flow(
		"Unmanaged encrypted DNS bypasses local resolver policy",
		"Encrypted DNS provides real privacy benefits. The defensive goal is managed, proportionate policy rather than disabling encryption indiscriminately.",
		[]FlowActor{
			actor("process", "Unmanaged process", "uses built-in DoH/DoT", "attacker"),
			actor("managed", "Enterprise resolver", "provides local policy", "resolver"),
			actor("external", "External DoH service", "resolves outside policy", "infrastructure"),
			actor("c2", "Blocked destination", "receives resolved traffic", "target"),
			actor("endpoint", "Endpoint/network policy", "governs resolver choice", "defense"),
		},
		[]FlowEvent{
			event("process", "managed", "Local DNS policy avoided", "The application does not send the lookup through the resolver where filtering and approved telemetry live.", "warning"),
			event("process", "external", "Encrypted DNS over HTTPS/TLS", "The query blends with permitted encrypted traffic to an unmanaged resolver.", "malicious"),
			event("external", "process", "Answer outside local controls", "A command-and-control or otherwise blocked name can resolve successfully.", "malicious"),
			event("process", "c2", "Follow-on connection", "Endpoint and connection telemetry may still expose the destination and originating process.", "warning"),
			event("endpoint", "process", "Managed encrypted DNS", "Endpoint controls and resolver allowlists can preserve encryption while enforcing organizational policy and minimal logging.", "defense"),
		},
	),
	"lame-delegation": flow(
		"A valid-looking referral leads to unusable authority",
		"SERVFAIL is the visible symptom. Diagnosis compares parent NS/glue, child apex NS, reachability, and authoritative-answer behavior.",
		[]FlowActor{
			actor("client", "DNS client", "asks for child name", "user"),
			actor("resolver", "Recursive resolver", "walks delegation", "resolver"),
			actor("parent", "Parent zone", "publishes NS + glue", "infrastructure"),
			actor("child", "Broken child server", "unreachable or non-authoritative", "target"),
			actor("operator", "DNS operator", "checks both sides of cut", "defense"),
		},
		[]FlowEvent{
			event("client", "resolver", "Query child.example", "The client expects the recursive resolver to complete the hierarchy walk.", "normal"),
			event("resolver", "parent", "Request delegation", "The parent returns an NS set and possibly glue for the child zone.", "normal"),
			event("resolver", "child", "Non-recursive child query", "The delegated server times out, refuses, lacks AA, or depends on an unresolvable circular name.", "warning"),
			event("resolver", "client", "Retries exhausted: SERVFAIL", "The resolver cannot obtain an authoritative answer from the advertised delegation.", "warning"),
			event("operator", "child", "Repair NS/glue/authority", "Continuous checks and coordinated parent/child changes isolate and correct the mismatch.", "defense"),
		},
	),
}

func flow(title, caption string, actors []FlowActor, events []FlowEvent) AttackFlow {
	return AttackFlow{Title: title, Caption: caption, Actors: actors, Events: events}
}

func actor(id, label, role, kind string) FlowActor {
	return FlowActor{ID: id, Label: label, Role: role, Kind: kind}
}

func event(from, to, label, detail, kind string) FlowEvent {
	return FlowEvent{From: from, To: to, Label: label, Detail: detail, Kind: kind}
}
