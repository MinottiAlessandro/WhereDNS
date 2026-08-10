package dnsengine

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

type cacheEntry struct {
	Key       string    `json:"key"`
	Name      string    `json:"name"`
	Type      string    `json:"type"`
	Server    string    `json:"server"`
	StoredAt  time.Time `json:"stored_at"`
	ExpiresAt time.Time `json:"expires_at"`
	Wire      []byte    `json:"wire"`
}

type cacheFile struct {
	Version int                   `json:"version"`
	Entries map[string]cacheEntry `json:"entries"`
}

// Cache is a small TTL-aware, disk-backed cache. A blank path makes it memory-only.
type Cache struct {
	mu      sync.Mutex
	path    string
	entries map[string]cacheEntry
	now     func() time.Time
}

func DefaultCachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "wheredns", "cache.json")
}

func NewCache(path string) (*Cache, error) {
	c := &Cache{path: path, entries: make(map[string]cacheEntry), now: time.Now}
	if path == "" {
		return c, nil
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return nil, err
	}
	var f cacheFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	if f.Entries != nil {
		c.entries = f.Entries
	}
	c.pruneLocked()
	return c, nil
}

func (c *Cache) Path() string { return c.path }

func (c *Cache) Get(key string) ([]byte, time.Time, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[key]
	if !ok {
		return nil, time.Time{}, false, nil
	}
	if !c.now().Before(e.ExpiresAt) {
		delete(c.entries, key)
		return nil, time.Time{}, false, c.saveLocked()
	}
	return append([]byte(nil), e.Wire...), e.ExpiresAt, true, nil
}

func (c *Cache) Put(key, name, qtype, server string, wire []byte, ttl uint32) error {
	if ttl == 0 || len(wire) == 0 {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.now()
	c.entries[key] = cacheEntry{
		Key: key, Name: name, Type: qtype, Server: server,
		StoredAt: now, ExpiresAt: now.Add(time.Duration(ttl) * time.Second),
		Wire: append([]byte(nil), wire...),
	}
	return c.saveLocked()
}

func (c *Cache) List() []CacheEntryInfo {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.pruneLocked()
	now := c.now()
	out := make([]CacheEntryInfo, 0, len(c.entries))
	for _, e := range c.entries {
		out = append(out, CacheEntryInfo{
			Key: e.Key, Name: e.Name, Type: e.Type, Server: e.Server,
			StoredAt: e.StoredAt, ExpiresAt: e.ExpiresAt,
			Remaining: int64(e.ExpiresAt.Sub(now).Seconds()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ExpiresAt.Before(out[j].ExpiresAt) })
	return out
}

func (c *Cache) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
	if c.path == "" {
		return nil
	}
	if err := os.Remove(c.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (c *Cache) pruneLocked() {
	now := c.now()
	for key, e := range c.entries {
		if !now.Before(e.ExpiresAt) {
			delete(c.entries, key)
		}
	}
}

func (c *Cache) saveLocked() error {
	if c.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cacheFile{Version: 1, Entries: c.entries}, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, c.path)
}
