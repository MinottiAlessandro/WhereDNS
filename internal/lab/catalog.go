package lab

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

type Scenario struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Attack       string   `json:"attack"`
	Objective    string   `json:"objective"`
	Mode         string   `json:"mode"`
	Safety       string   `json:"safety"`
	Steps        []Step   `json:"steps"`
	Observations []string `json:"observations"`
	Defenses     []string `json:"defenses"`
}

type Step struct {
	Number      int    `json:"number"`
	Actor       string `json:"actor"`
	Action      string `json:"action"`
	Result      string `json:"result"`
	Explanation string `json:"explanation"`
}

type RunResult struct {
	Scenario      Scenario       `json:"scenario"`
	Metrics       []Metric       `json:"metrics,omitempty"`
	StudentChecks []StudentCheck `json:"student_checks"`
}

type Metric struct {
	Name        string  `json:"name"`
	Value       float64 `json:"value"`
	Unit        string  `json:"unit"`
	Explanation string  `json:"explanation"`
}

type StudentCheck struct {
	Question string `json:"question"`
	Answer   string `json:"answer"`
}

var scenarios = []Scenario{
	{
		ID: "cache-poisoning", Title: "A forged referral meets a hardened cache", Attack: "Cache poisoning", Mode: "deterministic simulation",
		Objective: "Recognize response matching, bailiwick, entropy, and DNSSEC as separate layers of cache-poisoning defense.",
		Safety:    "No packets are spoofed. The race and cache decisions are modeled entirely in memory.",
		Steps: []Step{
			{1, "Student resolver", "Queries 7f3a.bank.test A with a randomized ID and source port.", "An outstanding-question tuple is recorded.", "A safe resolver matches source/destination, transaction ID, question name, class, and type."},
			{2, "Simulated attacker", "Supplies a forged referral for test plus an unrelated bank.test address.", "The message loses the race or fails tuple matching.", "Random subdomains create misses, but strong entropy makes blind guessing expensive."},
			{3, "Resolver", "Evaluates Additional-section records.", "Out-of-bailiwick bank.test data is rejected.", "Glue is accepted only when it is needed for an in-bailiwick delegated name server."},
			{4, "DNSSEC validator", "Checks DS, DNSKEY, and RRSIG links to the trust anchor.", "Forged signed-zone data is classified bogus.", "DNSSEC protects data authenticity even if an attacker wins the packet race."},
		},
		Observations: []string{"Matching the transaction ID alone is insufficient", "Additional data is not automatically trustworthy", "DNSSEC validation and encrypted transport solve different threats"},
		Defenses:     []string{"Source-port and ID entropy", "Strict response/question matching", "Bailiwick enforcement", "DNS cookies", "DNSSEC validation"},
	},
	{
		ID: "rebinding", Title: "Public origin, private destination", Attack: "DNS rebinding", Mode: "deterministic simulation + loopback server",
		Objective: "See why low TTLs and address changes can cross a browser's network boundary without changing its same-origin hostname.",
		Safety:    "The optional live server binds only to loopback. No browser or internal service is contacted automatically.",
		Steps: []Step{
			{1, "Authoritative server", "Answers rebind.test A with 203.0.113.20 and TTL 1.", "Browser associates attacker content with the hostname.", "The first address is an RFC 5737 documentation address in this simulation."},
			{2, "Browser/resolver", "TTL expires and the hostname is queried again.", "The origin string is unchanged.", "Historically, same-origin policy keys on scheme/host/port, not the resolved IP."},
			{3, "Authoritative server", "Answers 127.0.0.1.", "A subsequent request could target a loopback service.", "This is why internal services must authenticate requests and validate Host/Origin."},
		},
		Observations: []string{"The hostname stays constant while its address class changes", "DNS pinning alone is not a complete defense"},
		Defenses:     []string{"Host and Origin validation", "Authentication and CSRF protection", "Resolver rebinding protection", "Browser private-network protections"},
	},
	{
		ID: "amplification", Title: "Reflection/amplification arithmetic", Attack: "DNS amplification DDoS", Mode: "offline size simulation",
		Objective: "Understand reflection and response/request ratios without generating traffic.",
		Safety:    "Only arithmetic is performed. The lab cannot send repeated or spoofed packets.",
		Steps: []Step{
			{1, "Simulated attacker", "Creates one 44-byte UDP DNS request with a victim source address.", "A reflector believes the victim sent it.", "Source spoofing is the reflection primitive."},
			{2, "Open resolver", "Returns a modeled 1,232-byte DNSSEC response.", "Traffic goes to the victim.", "EDNS and DNSSEC can make responses much larger than questions."},
			{3, "Network defender", "Applies source-address validation and closes open recursion.", "The reflection path is removed.", "BCP 38 addresses spoofing; resolver ACLs address abuse of recursion."},
		},
		Observations: []string{"Reflection selects the victim; amplification multiplies traffic", "Rate is intentionally absent from this safe lab"},
		Defenses:     []string{"BCP 38", "No open recursion", "Response-rate limiting", "Minimal ANY responses"},
	},
	{
		ID: "tunneling", Title: "Detect a DNS-shaped covert channel", Attack: "DNS tunneling", Mode: "offline detection exercise + loopback server",
		Objective: "Identify high-entropy labels, excessive uniqueness, and unusual TXT use while avoiding simplistic false positives.",
		Safety:    "Uses fixed example strings under .test and sends no data to the Internet.",
		Steps: []Step{
			{1, "Simulated endpoint", "Queries mfrggzdfmztwq2lk.tunnel.test TXT.", "The leftmost label resembles encoded data.", "Base32-like alphabets and long labels can be one signal, not proof."},
			{2, "Detector", "Combines label entropy, length, unique-name rate, TXT use, and timing.", "The sample is scored suspicious.", "Behavioral combinations reduce false positives from CDNs and service discovery."},
			{3, "Analyst", "Correlates the DNS client process and destination zone.", "A defensible incident decision is made.", "Endpoint context distinguishes malware from legitimate software."},
		},
		Observations: []string{"One long label is not enough to convict", "Managed resolver logs and endpoint telemetry complement each other"},
		Defenses:     []string{"Managed egress resolvers", "Behavioral detection", "Endpoint telemetry", "Proportionate metadata retention"},
	},
	{
		ID: "dnssec-bogus", Title: "Break the DNSSEC chain", Attack: "DNSSEC misconfiguration/downgrade", Mode: "deterministic simulation",
		Objective: "Distinguish secure, insecure, and bogus DNSSEC states.",
		Safety:    "Uses symbolic keys and signatures; no real zone is modified.",
		Steps: []Step{
			{1, "Parent zone", "Publishes DS digest K1 for signed.test.", "Validator expects a matching child key.", "An authenticated absence of DS would instead define an insecure delegation."},
			{2, "Child zone", "Publishes DNSKEY K2 after a faulty rollover.", "K2 does not match parent DS K1.", "Signed records are not enough; the chain must connect to the trust anchor."},
			{3, "Validator", "Verifies DS(K2) != K1.", "The answer is bogus and resolution returns SERVFAIL.", "A validator must not silently treat bogus data as unsigned."},
		},
		Observations: []string{"Bogus is different from deliberately unsigned/insecure", "SERVFAIL can be the correct secure outcome"},
		Defenses:     []string{"Automated key-rollover checks", "DS/DNSKEY monitoring", "Clock synchronization", "Fail closed for bogus data"},
	},
	{
		ID: "zone-transfer", Title: "An exposed zone inventory", Attack: "Unauthorized AXFR", Mode: "deterministic simulation",
		Objective: "Understand AXFR framing, why it uses TCP, and why transfers need authorization.",
		Safety:    "The lab returns only a fictitious .test inventory and never attempts AXFR against an external server.",
		Steps: []Step{
			{1, "Client", "Requests AXFR for corp.test over TCP.", "The example server fails to check its transfer ACL.", "AXFR is a legitimate replication operation, not inherently an attack."},
			{2, "Authoritative server", "Returns SOA, NS, address, mail, and internal-name records, then closing SOA.", "A fictitious topology is disclosed.", "Transfers serialize the zone, including names that ordinary guessing might miss."},
			{3, "Administrator", "Restricts transfers to authenticated secondaries with TSIG.", "Unauthorized requests are refused.", "Hidden hostnames should still not be treated as secrets."},
		},
		Observations: []string{"A complete AXFR begins and ends with the zone SOA", "TCP is normal for transfers"},
		Defenses:     []string{"Transfer ACLs", "TSIG", "Monitoring", "Appropriate exposure of internal zones"},
	},
	{
		ID: "lame-delegation", Title: "Follow a broken delegation", Attack: "Lame/cyclic delegation", Mode: "deterministic simulation + loopback server",
		Objective: "Diagnose parent/child NS mismatch, missing glue, and authoritative servers that refuse the delegated zone.",
		Safety:    "All names are under .test; the optional server is loopback-only.",
		Steps: []Step{
			{1, "Parent zone", "Delegates broken.test to ns1.broken.test.", "Glue points at an available server.", "A referral alone does not guarantee that the child server is correctly configured."},
			{2, "Child server", "Returns REFUSED and does not set AA.", "The resolver tries other NS targets and eventually returns SERVFAIL.", "A delegated server that is not authoritative is called lame."},
			{3, "Operator", "Compares parent NS, child apex NS, glue, reachability, and AA behavior.", "The mismatch is isolated.", "Check both sides of a zone cut during changes."},
		},
		Observations: []string{"Delegation data exists at both parent and child", "SERVFAIL is a symptom, not a single diagnosis"},
		Defenses:     []string{"Continuous delegation monitoring", "Coordinated changes", "Multiple diverse authoritative servers", "Correct glue"},
	},
}

func Scenarios() []Scenario {
	out := append([]Scenario(nil), scenarios...)
	sort.Slice(out, func(i, j int) bool { return out[i].Title < out[j].Title })
	return out
}

func ScenarioByID(id string) (Scenario, bool) {
	id = strings.ToLower(strings.TrimSpace(id))
	for _, scenario := range scenarios {
		if scenario.ID == id {
			return scenario, true
		}
	}
	return Scenario{}, false
}

func Run(id string) (RunResult, error) {
	scenario, ok := ScenarioByID(id)
	if !ok {
		return RunResult{}, fmt.Errorf("unknown lab scenario %q", id)
	}
	result := RunResult{Scenario: scenario}
	switch scenario.ID {
	case "amplification":
		request, response := 44.0, 1232.0
		result.Metrics = []Metric{
			{Name: "request size", Value: request, Unit: "bytes", Explanation: "Modeled DNS request including its DNS payload; link/IP overhead varies."},
			{Name: "response size", Value: response, Unit: "bytes", Explanation: "A plausible fragmentation-conscious EDNS response ceiling."},
			{Name: "amplification factor", Value: math.Round(response/request*10) / 10, Unit: "×", Explanation: "Response bytes divided by request bytes; no traffic rate is modeled."},
		}
		result.StudentChecks = []StudentCheck{{"Which control stops reflection closest to its source?", "Source-address validation (BCP 38)."}, {"Which resolver control removes the open-recursion reflector?", "Allow recursion only for authorized clients."}}
	case "cache-poisoning":
		result.Metrics = []Metric{{Name: "modeled entropy", Value: 32, Unit: "bits", Explanation: "Approximately 16 transaction-ID bits plus 16 source-port bits before other mitigations."}}
		result.StudentChecks = []StudentCheck{{"Why reject bank.test from a referral for test?", "It is unrelated/out of bailiwick and is not necessary glue."}, {"What protects authenticity if a forged packet wins?", "A valid DNSSEC chain and signature verification."}}
	case "rebinding":
		result.StudentChecks = []StudentCheck{{"What remains unchanged across the two answers?", "The URL hostname/origin string."}, {"What must an internal HTTP service validate?", "Authentication plus expected Host and Origin, not only the client's network location."}}
	case "tunneling":
		result.Metrics = []Metric{{Name: "sample label length", Value: 16, Unit: "characters", Explanation: "Length alone is weak; combine it with entropy, uniqueness, type, and timing."}}
		result.StudentChecks = []StudentCheck{{"Is one encoded-looking query proof?", "No. Correlate repeated behavior, authoritative zone, and endpoint process."}}
	case "dnssec-bogus":
		result.StudentChecks = []StudentCheck{{"Should the validator downgrade this to unsigned?", "No. A broken expected chain is bogus and must fail validation."}}
	case "zone-transfer":
		result.StudentChecks = []StudentCheck{{"Is AXFR always malicious?", "No. It is normal secondary replication; authorization is the key."}}
	case "lame-delegation":
		result.StudentChecks = []StudentCheck{{"Which flag is missing from a lame server's useful answer?", "AA, the Authoritative Answer flag."}}
	}
	return result, nil
}
