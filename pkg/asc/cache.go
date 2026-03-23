package asc

import (
	"encoding/json"
	"fmt"
	"sync"

	lru "github.com/hashicorp/golang-lru/v2"
)

// ResultCache stores serialized flow results for short-lived in-process reuse.
type ResultCache interface {
	Get(key string) (map[string]any, bool, error)
	Add(key string, value map[string]any) error
}

// LRUResultCache is a threadsafe in-memory LRU cache implementation.
type LRUResultCache struct {
	mu  sync.Mutex
	lru *lru.Cache[string, []byte]
}

func NewLRUResultCache(size int) (*LRUResultCache, error) {
	if size < 1 {
		return nil, fmt.Errorf("cache size must be >= 1")
	}
	store, err := lru.New[string, []byte](size)
	if err != nil {
		return nil, fmt.Errorf("init lru cache: %w", err)
	}
	return &LRUResultCache{lru: store}, nil
}

func (c *LRUResultCache) Get(key string) (map[string]any, bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	blob, ok := c.lru.Get(key)
	if !ok {
		return nil, false, nil
	}
	var out map[string]any
	if err := json.Unmarshal(blob, &out); err != nil {
		return nil, false, fmt.Errorf("decode cached result: %w", err)
	}
	return out, true, nil
}

func (c *LRUResultCache) Add(key string, value map[string]any) error {
	blob, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode cached result: %w", err)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.lru.Add(key, blob)
	return nil
}
