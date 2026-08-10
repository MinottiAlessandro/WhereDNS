package webui

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/MinottiAlessandro/WhereDNS/internal/dnsengine"
	"github.com/MinottiAlessandro/WhereDNS/internal/lab"
	"github.com/MinottiAlessandro/WhereDNS/internal/learn"
)

//go:embed static/*
var staticFiles embed.FS

type Server struct {
	Engine *dnsengine.Engine
}

func New(engine *dnsengine.Engine) *Server { return &Server{Engine: engine} }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	assets, _ := fs.Sub(staticFiles, "static")
	mux.Handle("GET /", http.FileServer(http.FS(assets)))
	mux.HandleFunc("GET /api/health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "cache_path": s.Engine.Cache.Path()})
	})
	mux.HandleFunc("POST /api/query", s.handleQuery)
	mux.HandleFunc("POST /api/trace", s.handleTrace)
	mux.HandleFunc("GET /api/cache", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, s.Engine.Cache.List()) })
	mux.HandleFunc("DELETE /api/cache", func(w http.ResponseWriter, _ *http.Request) {
		if err := s.Engine.Cache.Clear(); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]bool{"cleared": true})
	})
	mux.HandleFunc("GET /api/topics", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, learn.Topics()) })
	mux.HandleFunc("GET /api/attacks", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, learn.Attacks()) })
	mux.HandleFunc("GET /api/labs", func(w http.ResponseWriter, _ *http.Request) { writeJSON(w, http.StatusOK, lab.Scenarios()) })
	mux.HandleFunc("POST /api/labs/{id}", func(w http.ResponseWriter, r *http.Request) {
		result, err := lab.Run(r.PathValue("id"))
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, result)
	})
	return securityHeaders(limitBody(mux))
}

func (s *Server) handleQuery(w http.ResponseWriter, r *http.Request) {
	options, err := decodeOptions(r)
	if err != nil {
		writeError(w, err)
		return
	}
	result, err := s.Engine.Query(r.Context(), options)
	if err != nil {
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleTrace(w http.ResponseWriter, r *http.Request) {
	options, err := decodeOptions(r)
	if err != nil {
		writeError(w, err)
		return
	}
	options.RecursionDesired = false
	result, err := s.Engine.Trace(r.Context(), options)
	if err != nil {
		if result != nil {
			writeJSON(w, http.StatusBadGateway, map[string]any{"error": err.Error(), "partial": result})
			return
		}
		writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func decodeOptions(r *http.Request) (dnsengine.QueryOptions, error) {
	var options dnsengine.QueryOptions
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&options); err != nil {
		return options, fmt.Errorf("invalid JSON request: %w", err)
	}
	if options.Type == "" {
		options.Type = "A"
	}
	if options.Transport == "" {
		options.Transport = "udp"
	}
	if options.EDNSSize == 0 {
		options.EDNSSize = 1232
	}
	options.Timeout = 7 * time.Second
	return options, nil
}

func ListenAndServe(ctx context.Context, address string, handler http.Handler) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid web listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
		return errors.New("the web learning interface may bind only to localhost or an explicit loopback address")
	}
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	errCh := make(chan error, 1)
	go func() { errCh <- server.ListenAndServe() }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/") && r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		}
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}
