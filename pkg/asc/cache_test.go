package asc

import "testing"

func TestNewLRUResultCache_SizeValidation(t *testing.T) {
	if _, err := NewLRUResultCache(0); err == nil {
		t.Fatal("expected error for zero cache size")
	}
}

func TestLRUResultCache_AddGet(t *testing.T) {
	cache, err := NewLRUResultCache(4)
	if err != nil {
		t.Fatal(err)
	}

	value := map[string]any{"ok": true, "count": float64(1)}
	if err := cache.Add("k1", value); err != nil {
		t.Fatal(err)
	}

	got, ok, err := cache.Get("k1")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("expected cache hit")
	}
	if got["ok"] != true {
		t.Fatalf("unexpected ok value: %v", got["ok"])
	}
	if got["count"] != float64(1) {
		t.Fatalf("unexpected count value: %v", got["count"])
	}
}
