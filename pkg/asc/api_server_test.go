package asc

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestApplySelectiveDisclosure(t *testing.T) {
	input := map[string]any{
		"campaign": map[string]any{
			"campaign_id": "campaign://luxury-targeting",
			"verifier_id": "verifier://ads-harvester",
		},
		"verification_receipt": map[string]any{
			"accepted":         true,
			"proof_size_bytes": 712,
		},
		"proof_bundle_wire": map[string]any{
			"asc_meta": map[string]any{
				"nullifier": "abc",
			},
		},
	}

	out := applySelectiveDisclosure(input, []string{
		"campaign.campaign_id",
		"verification_receipt.accepted",
	})

	campaign, ok := out["campaign"].(map[string]any)
	if !ok {
		t.Fatalf("expected campaign object")
	}
	if campaign["campaign_id"] != "campaign://luxury-targeting" {
		t.Fatalf("unexpected campaign_id: %v", campaign["campaign_id"])
	}
	if _, ok := campaign["verifier_id"]; ok {
		t.Fatalf("unexpected undisclosed field: verifier_id")
	}

	receipt, ok := out["verification_receipt"].(map[string]any)
	if !ok {
		t.Fatalf("expected verification_receipt object")
	}
	if accepted, _ := receipt["accepted"].(bool); !accepted {
		t.Fatalf("expected accepted=true")
	}
	if _, ok := receipt["proof_size_bytes"]; ok {
		t.Fatalf("unexpected undisclosed field: proof_size_bytes")
	}
	if _, ok := out["proof_bundle_wire"]; ok {
		t.Fatalf("unexpected undisclosed top-level field")
	}
}

func TestDeriveWalletSecretHexFromPrivateHex(t *testing.T) {
	seed := sha256.Sum256([]byte("nessa-api-wallet-test"))
	priv := ed25519.NewKeyFromSeed(seed[:])
	seedHex := hex.EncodeToString(seed[:])
	privHex := hex.EncodeToString(priv)

	fromSeed, err := deriveWalletSecretHexFromPrivateHex(seedHex)
	if err != nil {
		t.Fatalf("derive from seed: %v", err)
	}
	fromPriv, err := deriveWalletSecretHexFromPrivateHex(privHex)
	if err != nil {
		t.Fatalf("derive from private key: %v", err)
	}
	if fromSeed != fromPriv {
		t.Fatalf("expected stable wallet secret from seed/private representations")
	}
}

func TestNormalizeMode(t *testing.T) {
	cases := map[string]string{
		"":                 "verifier_centric",
		"verifier":         "verifier_centric",
		"verifier-centric": "verifier_centric",
		"user":             "user_centric",
		"user-centric":     "user_centric",
	}

	for input, expected := range cases {
		got := normalizeMode(input)
		if got != expected {
			t.Fatalf("normalizeMode(%q)=%q want=%q", input, got, expected)
		}
	}
}
