package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/miekg/dns"

	"github.com/MinottiAlessandro/WhereDNS/internal/dnsengine"
	"github.com/MinottiAlessandro/WhereDNS/internal/lab"
	"github.com/MinottiAlessandro/WhereDNS/internal/learn"
	"github.com/MinottiAlessandro/WhereDNS/internal/webui"
)

// Version is replaced from the Git tag in release builds.
var Version = "0.2.0"

type App struct {
	ctx    context.Context
	engine *dnsengine.Engine
	out    io.Writer
	errOut io.Writer
}

func New(ctx context.Context, engine *dnsengine.Engine, out, errOut io.Writer) *App {
	return &App{ctx: ctx, engine: engine, out: out, errOut: errOut}
}

func (a *App) Run(args []string) error {
	if len(args) == 0 {
		a.usage()
		return nil
	}
	switch args[0] {
	case "help", "-h", "--help":
		a.usage()
		return nil
	case "version", "--version":
		fmt.Fprintf(a.out, "WhereDNS %s\n", Version)
		return nil
	case "query":
		return a.runQuery(args[1:], "")
	case "reverse":
		return a.runReverse(args[1:])
	case "trace":
		return a.runTrace(args[1:])
	case "compare":
		return a.runCompare(args[1:])
	case "cache":
		return a.runCache(args[1:])
	case "learn":
		return a.runLearn(args[1:])
	case "attacks", "attack":
		return a.runAttacks(args[1:])
	case "lab":
		return a.runLab(args[1:])
	case "serve", "web":
		return a.runServe(args[1:])
	case "types":
		return a.runTypes(args[1:])
	default:
		return fmt.Errorf("unknown command %q; run 'wheredns help'", args[0])
	}
}

func (a *App) usage() {
	fmt.Fprintln(a.out, `WhereDNS — learn DNS by seeing the protocol

Usage:
  wheredns query NAME [options]       inspect one recursive/direct DNS exchange
  wheredns trace NAME [options]       walk root -> TLD -> authoritative servers
  wheredns reverse IP [options]       construct and query the reverse-DNS PTR name
  wheredns compare NAME [options]     compare answers from multiple resolvers
  wheredns cache list|clear|path      inspect the explicit TTL-aware cache
  wheredns learn [TOPIC]              study protocol foundations
  wheredns attacks [ATTACK]           study attack mechanics, signals, and defenses
  wheredns lab list|run|server         use isolated DNS security exercises
  wheredns serve [options]            launch the optional loopback-only web UI
  wheredns types                      list understood DNS record types

Start here:
  wheredns query example.com --type A
  wheredns trace example.com --type MX --no-cache
  wheredns attacks cache-poisoning
  wheredns lab run cache-poisoning
  wheredns serve

Options may follow NAME. Run 'wheredns COMMAND --help' for command flags.`)
}

type queryFlags struct {
	typeName         string
	server           string
	transport        string
	cache            bool
	noCache          bool
	dnssec           bool
	recursion        bool
	checkingDisabled bool
	ednsSize         uint
	timeout          time.Duration
	json             bool
	wire             bool
}

func (a *App) queryFlagSet(command string, args []string) (*flag.FlagSet, queryFlags, string, error) {
	fs := flag.NewFlagSet(command, flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	var q queryFlags
	fs.StringVar(&q.typeName, "type", "A", "record type (A, AAAA, MX, DNSKEY, TYPE####, ...)")
	fs.StringVar(&q.server, "server", "", "resolver HOST[:PORT], or HTTPS endpoint for DoH")
	fs.StringVar(&q.transport, "transport", "udp", "udp, tcp, dot, or doh")
	fs.BoolVar(&q.cache, "cache", true, "read and populate the WhereDNS cache")
	fs.BoolVar(&q.noCache, "no-cache", false, "bypass and do not populate the WhereDNS cache")
	fs.BoolVar(&q.dnssec, "dnssec", true, "set EDNS DO and inspect DNSSEC evidence")
	fs.BoolVar(&q.recursion, "rd", true, "set Recursion Desired")
	fs.BoolVar(&q.checkingDisabled, "cd", false, "set Checking Disabled for DNSSEC diagnostics")
	fs.UintVar(&q.ednsSize, "edns-size", 1232, "advertised UDP payload size")
	fs.DurationVar(&q.timeout, "timeout", 5*time.Second, "network timeout")
	fs.BoolVar(&q.json, "json", false, "emit machine-readable JSON")
	fs.BoolVar(&q.wire, "wire", false, "include a hexadecimal wire dump")
	leadingName, parseArgs := leadingPositional(args)
	if err := fs.Parse(parseArgs); err != nil {
		return nil, q, "", err
	}
	name := leadingName
	if name == "" && fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	usedArgs := fs.NArg()
	if leadingName == "" && name != "" {
		usedArgs--
	}
	if usedArgs > 0 {
		return nil, q, "", fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args()[fs.NArg()-usedArgs:], " "))
	}
	return fs, q, name, nil
}

func (q queryFlags) options(name string) (dnsengine.QueryOptions, error) {
	if q.ednsSize > 65535 {
		return dnsengine.QueryOptions{}, errors.New("EDNS size must fit in 16 bits")
	}
	return dnsengine.QueryOptions{
		Name: name, Type: q.typeName, Server: q.server, Transport: q.transport,
		UseCache: q.cache && !q.noCache, DNSSEC: q.dnssec,
		RecursionDesired: q.recursion, CheckingDisabled: q.checkingDisabled,
		EDNSSize: uint16(q.ednsSize), Timeout: q.timeout,
	}, nil
}

func (a *App) runQuery(args []string, forcedName string) error {
	_, flags, name, err := a.queryFlagSet("query", args)
	if err != nil {
		return err
	}
	if forcedName != "" {
		name = forcedName
	}
	if name == "" {
		return errors.New("query requires NAME")
	}
	options, err := flags.options(name)
	if err != nil {
		return err
	}
	result, err := a.engine.Query(a.ctx, options)
	if err != nil {
		return err
	}
	if flags.json {
		return printJSON(a.out, result)
	}
	printResult(a.out, result, flags.wire)
	return nil
}

func (a *App) runReverse(args []string) error {
	if len(args) == 0 {
		return errors.New("reverse requires an IPv4 or IPv6 address")
	}
	ip, rest := args[0], args[1:]
	if strings.HasPrefix(ip, "-") {
		return errors.New("put the IP address before reverse-query options")
	}
	name, err := dnsengine.ReverseName(ip)
	if err != nil {
		return err
	}
	rest = append(rest, "--type", "PTR")
	return a.runQuery(rest, name)
}

func (a *App) runTrace(args []string) error {
	_, flags, name, err := a.queryFlagSet("trace", args)
	if err != nil {
		return err
	}
	if name == "" {
		return errors.New("trace requires NAME")
	}
	options, err := flags.options(name)
	if err != nil {
		return err
	}
	options.RecursionDesired = false
	result, traceErr := a.engine.Trace(a.ctx, options)
	if flags.json {
		if result != nil {
			_ = printJSON(a.out, result)
		}
		return traceErr
	}
	if result != nil {
		printTrace(a.out, result)
	}
	return traceErr
}

func (a *App) runCompare(args []string) error {
	fs := flag.NewFlagSet("compare", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	typeName := fs.String("type", "A", "record type")
	serverList := fs.String("servers", "system,1.1.1.1,8.8.8.8", "comma-separated resolver addresses; 'system' uses resolv.conf")
	dnssec := fs.Bool("dnssec", true, "request DNSSEC")
	timeout := fs.Duration("timeout", 5*time.Second, "per-resolver timeout")
	jsonOutput := fs.Bool("json", false, "emit JSON")
	name, parseArgs := leadingPositional(args)
	if err := fs.Parse(parseArgs); err != nil {
		return err
	}
	if name == "" && fs.NArg() > 0 {
		name = fs.Arg(0)
	}
	if name == "" {
		return errors.New("compare requires NAME")
	}
	type comparison struct {
		Server string            `json:"server"`
		Result *dnsengine.Result `json:"result,omitempty"`
		Error  string            `json:"error,omitempty"`
	}
	var comparisons []comparison
	for _, server := range strings.Split(*serverList, ",") {
		server = strings.TrimSpace(server)
		if server == "system" {
			server = ""
		}
		result, err := a.engine.Query(a.ctx, dnsengine.QueryOptions{Name: name, Type: *typeName, Server: server, Transport: "udp", UseCache: false, DNSSEC: *dnssec, RecursionDesired: true, EDNSSize: 1232, Timeout: *timeout})
		item := comparison{Server: server, Result: result}
		if server == "" {
			item.Server = "system"
		}
		if err != nil {
			item.Error = err.Error()
		}
		comparisons = append(comparisons, item)
	}
	if *jsonOutput {
		return printJSON(a.out, comparisons)
	}
	w := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "RESOLVER\tSTATUS\tTIME\tANSWER DATA")
	for _, item := range comparisons {
		if item.Error != "" {
			fmt.Fprintf(w, "%s\tERROR\t-\t%s\n", item.Server, item.Error)
			continue
		}
		var data []string
		for _, record := range item.Result.Records {
			if record.Section == "answer" {
				data = append(data, record.Data)
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%.2f ms\t%s\n", item.Result.Server, item.Result.Rcode, item.Result.DurationMS, strings.Join(data, " | "))
	}
	return w.Flush()
}

func (a *App) runCache(args []string) error {
	if len(args) == 0 {
		return errors.New("cache requires list, clear, or path")
	}
	switch args[0] {
	case "path":
		if a.engine.Cache.Path() == "" {
			fmt.Fprintln(a.out, "memory-only")
		} else {
			fmt.Fprintln(a.out, a.engine.Cache.Path())
		}
	case "clear":
		if err := a.engine.Cache.Clear(); err != nil {
			return err
		}
		fmt.Fprintln(a.out, "Cache cleared.")
	case "list":
		entries := a.engine.Cache.List()
		if len(entries) == 0 {
			fmt.Fprintln(a.out, "Cache is empty.")
			return nil
		}
		w := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tTYPE\tSERVER\tREMAINING\tEXPIRES")
		for _, entry := range entries {
			fmt.Fprintf(w, "%s\t%s\t%s\t%ds\t%s\n", entry.Name, entry.Type, entry.Server, entry.Remaining, entry.ExpiresAt.Format(time.RFC3339))
		}
		return w.Flush()
	default:
		return fmt.Errorf("unknown cache action %q", args[0])
	}
	return nil
}

func (a *App) runLearn(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		fmt.Fprintln(a.out, "DNS LEARNING TOPICS")
		for _, topic := range learn.Topics() {
			fmt.Fprintf(a.out, "  %-14s %s\n", topic.ID, topic.Title)
		}
		fmt.Fprintln(a.out, "\nUse: wheredns learn TOPIC")
		return nil
	}
	topic, ok := learn.TopicByID(args[0])
	if !ok {
		return fmt.Errorf("unknown topic %q", args[0])
	}
	fmt.Fprintf(a.out, "%s\n%s\n\n%s\n\nKey concepts:\n", topic.Title, strings.Repeat("=", len(topic.Title)), topic.Summary)
	for _, concept := range topic.Concepts {
		fmt.Fprintf(a.out, "  - %s\n", concept)
	}
	fmt.Fprintln(a.out, "\nTry it:")
	for _, command := range topic.Try {
		fmt.Fprintf(a.out, "  $ %s\n", command)
	}
	return nil
}

func (a *App) runAttacks(args []string) error {
	jsonOutput := false
	if len(args) > 0 && args[len(args)-1] == "--json" {
		jsonOutput = true
		args = args[:len(args)-1]
	}
	if len(args) == 0 || args[0] == "list" {
		items := learn.Attacks()
		if jsonOutput {
			return printJSON(a.out, items)
		}
		w := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tRISK\tCATEGORY\tATTACK")
		for _, attack := range items {
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", attack.ID, strings.ToUpper(attack.Risk), attack.Category, attack.Name)
		}
		_ = w.Flush()
		fmt.Fprintln(a.out, "\nUse: wheredns attacks ATTACK-ID")
		return nil
	}
	attack, ok := learn.AttackByID(args[0])
	if !ok {
		return fmt.Errorf("unknown attack %q", args[0])
	}
	if jsonOutput {
		return printJSON(a.out, attack)
	}
	fmt.Fprintf(a.out, "%s [%s]\n%s\n\n%s\n", attack.Name, strings.ToUpper(attack.Risk), strings.Repeat("=", len(attack.Name)+len(attack.Risk)+3), attack.Summary)
	printList(a.out, "Mechanism", attack.Mechanism)
	printList(a.out, "Prerequisites", attack.Prerequisites)
	printList(a.out, "Observable signals", attack.Signals)
	printList(a.out, "Defenses", attack.Defenses)
	if attack.LabScenario != "" {
		fmt.Fprintf(a.out, "\nSafe lab: wheredns lab run %s\n", attack.LabScenario)
	}
	fmt.Fprintf(a.out, "\nEthics: %s\n", attack.Ethics)
	return nil
}

func (a *App) runLab(args []string) error {
	if len(args) == 0 || args[0] == "list" {
		w := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "ID\tMODE\tSCENARIO")
		for _, scenario := range lab.Scenarios() {
			fmt.Fprintf(w, "%s\t%s\t%s\n", scenario.ID, scenario.Mode, scenario.Title)
		}
		_ = w.Flush()
		fmt.Fprintln(a.out, "\nRun a simulation: wheredns lab run SCENARIO")
		fmt.Fprintln(a.out, "Run a loopback server: wheredns lab server --scenario basic")
		return nil
	}
	switch args[0] {
	case "run":
		if len(args) < 2 {
			return errors.New("lab run requires SCENARIO")
		}
		jsonOutput := len(args) > 2 && args[2] == "--json"
		result, err := lab.Run(args[1])
		if err != nil {
			return err
		}
		if jsonOutput {
			return printJSON(a.out, result)
		}
		printLab(a.out, result)
		return nil
	case "server":
		fs := flag.NewFlagSet("lab server", flag.ContinueOnError)
		fs.SetOutput(a.errOut)
		scenario := fs.String("scenario", "basic", "basic, cache-poisoning, rebinding, tunneling, or lame-delegation")
		listen := fs.String("listen", "127.0.0.1:15353", "explicit loopback listen address")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		fmt.Fprintf(a.out, "WhereDNS lab server: %s on udp+tcp://%s\n", *scenario, *listen)
		fmt.Fprintf(a.out, "Try: wheredns query learn.test --server %s --no-cache\n", *listen)
		fmt.Fprintln(a.out, "Press Ctrl-C to stop. The server refuses non-loopback bind addresses.")
		return lab.Serve(a.ctx, *scenario, *listen)
	default:
		return fmt.Errorf("unknown lab action %q", args[0])
	}
}

func (a *App) runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	fs.SetOutput(a.errOut)
	listen := fs.String("listen", "127.0.0.1:8080", "loopback listen address")
	if err := fs.Parse(args); err != nil {
		return err
	}
	fmt.Fprintf(a.out, "WhereDNS web interface: http://%s\n", *listen)
	fmt.Fprintln(a.out, "The CLI remains fully standalone. Press Ctrl-C to stop.")
	return webui.ListenAndServe(a.ctx, *listen, webui.New(a.engine).Handler())
}

func (a *App) runTypes(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("types takes no arguments")
	}
	type pair struct {
		code uint16
		name string
	}
	values := make([]pair, 0, len(dns.TypeToString))
	for code, name := range dns.TypeToString {
		values = append(values, pair{code, name})
	}
	sort.Slice(values, func(i, j int) bool { return values[i].code < values[j].code })
	w := tabwriter.NewWriter(a.out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "CODE\tTYPE\tDESCRIPTION")
	for _, value := range values {
		fmt.Fprintf(w, "%d\t%s\t%s\n", value.code, value.name, briefType(value.code))
	}
	return w.Flush()
}

func printResult(out io.Writer, result *dnsengine.Result, wire bool) {
	fmt.Fprintf(out, "%s %s\n", result.Question.Name, result.Question.Type)
	fmt.Fprintln(out, strings.Repeat("=", len(result.Question.Name)+len(result.Question.Type)+1))
	source := "network"
	if result.FromCache {
		source = "WhereDNS cache"
	}
	fmt.Fprintf(out, "Server:    %s via %s\nStatus:    %s (%d)\nSource:    %s\nDuration:  %.2f ms\nMessage:   id=%d, %d-byte response\n", result.Server, result.Transport, result.Rcode, result.RcodeNumber, source, result.DurationMS, result.MessageID, result.Wire.ResponseBytes)
	fmt.Fprint(out, "Flags:     ")
	for _, flag := range result.Flags {
		if flag.Enabled {
			fmt.Fprintf(out, "%s ", flag.Code)
		}
	}
	fmt.Fprintln(out)
	fmt.Fprintf(out, "DNSSEC:    %s\n", result.DNSSEC.Status)
	if result.EDNS != nil {
		fmt.Fprintf(out, "EDNS:      version %d, UDP %d, DO=%t\n", result.EDNS.Version, result.EDNS.UDPSize, result.EDNS.DNSSECOK)
	}

	if len(result.Records) == 0 {
		fmt.Fprintln(out, "\nRecords: none")
	} else {
		w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintln(w, "\nSECTION\tNAME\tTTL\tTYPE\tDATA")
		for _, record := range result.Records {
			fmt.Fprintf(w, "%s\t%s\t%d\t%s\t%s\n", strings.ToUpper(record.Section), record.Name, record.TTL, record.Type, record.Data)
		}
		_ = w.Flush()
	}
	fmt.Fprintf(out, "\nDNSSEC reading: %s\n", result.DNSSEC.Explanation)
	for _, explanation := range result.Explanations {
		fmt.Fprintf(out, "- %s: %s\n", explanation.Subject, explanation.Text)
	}
	for _, warning := range result.Warnings {
		fmt.Fprintf(out, "! %s\n", warning)
	}
	if result.CacheExpires != nil {
		fmt.Fprintf(out, "Cache expiry: %s\n", result.CacheExpires.Format(time.RFC3339))
	}
	if wire {
		fmt.Fprintf(out, "\nQUERY WIRE (%d bytes)\n%s\nRESPONSE WIRE (%d bytes)\n%s", result.Wire.QueryBytes, result.Wire.QueryHex, result.Wire.ResponseBytes, result.Wire.ResponseHex)
	}
}

func printTrace(out io.Writer, trace *dnsengine.TraceResult) {
	fmt.Fprintf(out, "Iterative trace: %s %s\n%s\n", trace.Name, trace.Type, strings.Repeat("=", len(trace.Name)+len(trace.Type)+18))
	for _, step := range trace.Steps {
		fmt.Fprintf(out, "\n%d. %s — %s (%s)\n   %s · %s · %.2f ms\n   %s\n", step.Number, strings.ToUpper(step.Role), step.Server, step.Address, step.Event, step.Rcode, step.DurationMS, step.Explanation)
		for _, record := range step.Records {
			fmt.Fprintf(out, "   %-10s %-7s %s\n", strings.ToUpper(record.Section), record.Type, record.Data)
		}
	}
	fmt.Fprintf(out, "\nComplete: %t · %d hops · %.2f ms\n", trace.Complete, len(trace.Steps), trace.DurationMS)
}

func printLab(out io.Writer, result lab.RunResult) {
	s := result.Scenario
	fmt.Fprintf(out, "%s\n%s\nAttack: %s\nMode: %s\n\nObjective: %s\nSafety: %s\n", s.Title, strings.Repeat("=", len(s.Title)), s.Attack, s.Mode, s.Objective, s.Safety)
	for _, step := range s.Steps {
		fmt.Fprintf(out, "\n%d. %s\n   Action: %s\n   Result: %s\n   Why: %s\n", step.Number, step.Actor, step.Action, step.Result, step.Explanation)
	}
	for _, metric := range result.Metrics {
		fmt.Fprintf(out, "\nMetric — %s: %s %s\n  %s\n", metric.Name, strconv.FormatFloat(metric.Value, 'f', -1, 64), metric.Unit, metric.Explanation)
	}
	printList(out, "What to observe", s.Observations)
	printList(out, "Defenses", s.Defenses)
	if len(result.StudentChecks) > 0 {
		fmt.Fprintln(out, "\nCheck your model")
		for _, check := range result.StudentChecks {
			fmt.Fprintf(out, "  Q: %s\n  A: %s\n", check.Question, check.Answer)
		}
	}
}

func printList(out io.Writer, title string, values []string) {
	fmt.Fprintf(out, "\n%s\n", title)
	for _, value := range values {
		fmt.Fprintf(out, "  - %s\n", value)
	}
}

func printJSON(out io.Writer, value any) error {
	encoder := json.NewEncoder(out)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func leadingPositional(args []string) (string, []string) {
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		return args[0], args[1:]
	}
	return "", args
}

func briefType(code uint16) string {
	values := map[uint16]string{
		dns.TypeA: "IPv4 address", dns.TypeAAAA: "IPv6 address", dns.TypeCNAME: "canonical-name alias",
		dns.TypeMX: "mail exchanger", dns.TypeNS: "authoritative name server", dns.TypeSOA: "start of authority",
		dns.TypeTXT: "text data", dns.TypePTR: "reverse pointer", dns.TypeSRV: "service locator",
		dns.TypeCAA: "certificate-authority authorization", dns.TypeDNSKEY: "DNSSEC public key", dns.TypeDS: "DNSSEC parent digest",
		dns.TypeRRSIG: "DNSSEC signature", dns.TypeNSEC: "authenticated denial", dns.TypeNSEC3: "hashed authenticated denial",
		dns.TypeHTTPS: "HTTPS service binding", dns.TypeSVCB: "service binding", dns.TypeTLSA: "DANE TLS association",
	}
	return values[code]
}
