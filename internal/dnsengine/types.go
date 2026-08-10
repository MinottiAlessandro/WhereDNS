package dnsengine

import "time"

// QueryOptions controls a single DNS exchange. It is shared by the CLI and web UI.
type QueryOptions struct {
	Name             string        `json:"name"`
	Type             string        `json:"type"`
	Server           string        `json:"server,omitempty"`
	Transport        string        `json:"transport"`
	UseCache         bool          `json:"use_cache"`
	DNSSEC           bool          `json:"dnssec"`
	RecursionDesired bool          `json:"recursion_desired"`
	CheckingDisabled bool          `json:"checking_disabled"`
	EDNSSize         uint16        `json:"edns_size"`
	Timeout          time.Duration `json:"-"`
}

type Result struct {
	Question     Question      `json:"question"`
	Server       string        `json:"server"`
	Transport    string        `json:"transport"`
	Timestamp    time.Time     `json:"timestamp"`
	DurationMS   float64       `json:"duration_ms"`
	FromCache    bool          `json:"from_cache"`
	CacheKey     string        `json:"cache_key,omitempty"`
	CacheExpires *time.Time    `json:"cache_expires,omitempty"`
	MessageID    uint16        `json:"message_id"`
	Rcode        string        `json:"rcode"`
	RcodeNumber  int           `json:"rcode_number"`
	Flags        []Flag        `json:"flags"`
	Records      []Record      `json:"records"`
	EDNS         *EDNSInfo     `json:"edns,omitempty"`
	DNSSEC       DNSSECInfo    `json:"dnssec"`
	Wire         WireInfo      `json:"wire"`
	Explanations []Explanation `json:"explanations"`
	Warnings     []string      `json:"warnings,omitempty"`
}

type Question struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class string `json:"class"`
}

type Flag struct {
	Code        string `json:"code"`
	Enabled     bool   `json:"enabled"`
	Explanation string `json:"explanation"`
}

type Record struct {
	Section     string `json:"section"`
	Name        string `json:"name"`
	TTL         uint32 `json:"ttl"`
	Class       string `json:"class"`
	Type        string `json:"type"`
	Data        string `json:"data"`
	Text        string `json:"text"`
	Explanation string `json:"explanation"`
}

type EDNSInfo struct {
	Version       uint8    `json:"version"`
	UDPSize       uint16   `json:"udp_size"`
	DNSSECOK      bool     `json:"dnssec_ok"`
	ExtendedRcode int      `json:"extended_rcode"`
	Options       []string `json:"options,omitempty"`
}

type DNSSECInfo struct {
	Requested        bool   `json:"requested"`
	Authenticated    bool   `json:"authenticated"`
	CheckingDisabled bool   `json:"checking_disabled"`
	HasSignatures    bool   `json:"has_signatures"`
	HasDenialProof   bool   `json:"has_denial_proof"`
	HasChainMaterial bool   `json:"has_chain_material"`
	Status           string `json:"status"`
	Explanation      string `json:"explanation"`
}

type WireInfo struct {
	QueryBytes    int    `json:"query_bytes"`
	ResponseBytes int    `json:"response_bytes"`
	QueryHex      string `json:"query_hex"`
	ResponseHex   string `json:"response_hex"`
}

type Explanation struct {
	Subject string `json:"subject"`
	Text    string `json:"text"`
}

type TraceResult struct {
	Name       string      `json:"name"`
	Type       string      `json:"type"`
	StartedAt  time.Time   `json:"started_at"`
	DurationMS float64     `json:"duration_ms"`
	Complete   bool        `json:"complete"`
	Steps      []TraceStep `json:"steps"`
	Warnings   []string    `json:"warnings,omitempty"`
}

type TraceStep struct {
	Number      int      `json:"number"`
	Role        string   `json:"role"`
	Server      string   `json:"server"`
	Address     string   `json:"address"`
	Question    string   `json:"question"`
	Rcode       string   `json:"rcode"`
	DurationMS  float64  `json:"duration_ms"`
	Event       string   `json:"event"`
	Explanation string   `json:"explanation"`
	Records     []Record `json:"records"`
}

type CacheEntryInfo struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Server    string    `json:"server"`
	StoredAt  time.Time `json:"stored_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Remaining int64     `json:"remaining_seconds"`
}
