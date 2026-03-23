package asc

import "testing"

func TestDeriveSingleWalletCacheKey_IgnoresNonSemanticFields(t *testing.T) {
	reqA := map[string]any{
		"python_root":        "/a",
		"include_raw_bundle": true,
		"user_label":         "user://1",
		"campaign_id":        "campaign://luxury-targeting",
		"metadata": map[string]any{
			"age_band": float64(8),
		},
	}
	reqB := map[string]any{
		"python_root":        "/b",
		"include_raw_bundle": false,
		"user_label":         "user://1",
		"campaign_id":        "campaign://luxury-targeting",
		"metadata": map[string]any{
			"age_band": float64(8),
		},
	}

	ka, err := deriveSingleWalletCacheKey(reqA)
	if err != nil {
		t.Fatal(err)
	}
	kb, err := deriveSingleWalletCacheKey(reqB)
	if err != nil {
		t.Fatal(err)
	}
	if ka != kb {
		t.Fatalf("cache key mismatch for equivalent requests\nka=%s\nkb=%s", ka, kb)
	}
}
