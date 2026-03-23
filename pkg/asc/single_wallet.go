package asc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
)

const singleWalletScript = `import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

payload = json.loads(os.environ["NESSA_ASC_SINGLE_REQ"])
root = Path(payload["python_root"])
sys.path.insert(0, str(root))
impl = root / "impl"
if str(impl) not in sys.path:
    sys.path.insert(0, str(impl))

from asc_ad_demo import (
    AdCampaign,
    AdMetadataProfile,
    AdProverWallet,
    AdVerifier,
    build_default_campaigns,
)

campaigns = build_default_campaigns(
    verifier_id=payload["verifier_id"],
    campaign_window=payload["campaign_window"],
)
campaign = None
for entry in campaigns:
    if entry.campaign_id == payload["campaign_id"]:
        campaign = entry
        break

if campaign is None:
    campaign = AdCampaign(
        campaign_id=payload["campaign_id"],
        verifier_id=payload["verifier_id"],
        campaign_window=payload["campaign_window"],
        weight_profile=payload["weight_profile"],
        required_consent_mask=int(payload["required_consent_mask"]),
        min_age_band=int(payload["min_age_band"]),
        pseudonym_scope=payload["pseudonym_scope"],
    )

metadata = AdMetadataProfile(
    age_band=int(payload["metadata"]["age_band"]),
    interest_code=int(payload["metadata"]["interest_code"]),
    location_tier=int(payload["metadata"]["location_tier"]),
    device_class=int(payload["metadata"]["device_class"]),
    browsing_segment=int(payload["metadata"]["browsing_segment"]),
    income_bracket=int(payload["metadata"]["income_bracket"]),
    engagement_level=int(payload["metadata"]["engagement_level"]),
    consent_flags=int(payload["metadata"]["consent_flags"]),
)

wallet_secret_hex = str(payload.get("wallet_secret_hex", ""))
if wallet_secret_hex:
    wallet = AdProverWallet(
        payload["user_label"],
        payload["device_label"],
        bytes.fromhex(wallet_secret_hex),
    )
else:
    wallet = AdProverWallet.create(
        payload["user_label"],
        payload["device_label"],
        deterministic_secret=bool(payload["deterministic_secret"]),
    )
wallet.set_metadata(metadata)

prove_kwargs = {"deterministic": bool(payload["deterministic"])}
if int(payload.get("target_rows", 0)) > 0:
    prove_kwargs["target_rows"] = int(payload["target_rows"])

raw_bundle = wallet.prove_targeting(campaign, **prove_kwargs)
wire_bundle = wallet.redact_for_wire(raw_bundle)

verifier = AdVerifier([campaign])
receipt = verifier.verify_targeting(wire_bundle, campaign.campaign_id)

out = {
    "mode": "single_wallet_single_campaign",
    "campaign": {
        "campaign_id": campaign.campaign_id,
        "verifier_id": campaign.verifier_id,
        "campaign_window": campaign.campaign_window,
        "weight_profile": campaign.weight_profile,
        "required_consent_mask": campaign.required_consent_mask,
        "min_age_band": campaign.min_age_band,
        "pseudonym_scope": campaign.pseudonym_scope,
    },
    "user": {
        "user_label": payload["user_label"],
        "device_label": payload["device_label"],
        "metadata": payload["metadata"],
    },
    "proof_bundle_wire": wire_bundle,
    "verification_receipt": asdict(receipt),
}
if bool(payload.get("include_raw_bundle", False)):
    out["proof_bundle_raw"] = raw_bundle

print(json.dumps(out, sort_keys=True))
`

// MetadataProfile contains user metadata fields used by ASC.
type MetadataProfile struct {
	AgeBand         int `json:"age_band"`
	InterestCode    int `json:"interest_code"`
	LocationTier    int `json:"location_tier"`
	DeviceClass     int `json:"device_class"`
	BrowsingSegment int `json:"browsing_segment"`
	IncomeBracket   int `json:"income_bracket"`
	EngagementLevel int `json:"engagement_level"`
	ConsentFlags    int `json:"consent_flags"`
}

// SingleWalletVerifyOptions configures one prove+verify run for a user and campaign.
type SingleWalletVerifyOptions struct {
	UserLabel       string
	DeviceLabel     string
	WalletSecretHex string
	CampaignID      string
	VerifierID      string
	CampaignWindow  string
	WeightProfile   string
	PseudonymScope  string
	RequiredConsent int
	MinAgeBand      int
	Metadata        MetadataProfile
	Deterministic   bool

	DeterministicSecret bool
	TargetRows          int
	IncludeRawBundle    bool

	DisableCache bool
	CacheKey     string
	Cache        ResultCache

	PythonBinary string
	PythonRoot   string
}

var (
	defaultSingleWalletCacheOnce sync.Once
	defaultSingleWalletCache     ResultCache
	defaultSingleWalletCacheErr  error
)

func getDefaultSingleWalletCache() (ResultCache, error) {
	defaultSingleWalletCacheOnce.Do(func() {
		defaultSingleWalletCache, defaultSingleWalletCacheErr = NewLRUResultCache(256)
	})
	return defaultSingleWalletCache, defaultSingleWalletCacheErr
}

// RunSingleWalletVerify executes one user-centric ASC prove+verify flow backed by
// the Python protocol core and optionally caches the result in-memory.
func RunSingleWalletVerify(ctx context.Context, opts SingleWalletVerifyOptions) (map[string]any, error) {
	pythonRoot, err := resolvePythonRoot(opts.PythonRoot)
	if err != nil {
		return nil, err
	}
	pythonBin := resolvePythonBin(opts.PythonBinary)

	req := buildSingleWalletRequest(opts, pythonRoot)
	cacheKey := opts.CacheKey
	if cacheKey == "" {
		cacheKey, err = deriveSingleWalletCacheKey(req)
		if err != nil {
			return nil, err
		}
	}

	cache := opts.Cache
	if cache == nil {
		cache, err = getDefaultSingleWalletCache()
		if err != nil {
			return nil, err
		}
	}

	if !opts.DisableCache {
		if cached, ok, err := cache.Get(cacheKey); err != nil {
			return nil, err
		} else if ok {
			cached["cache"] = map[string]any{"hit": true, "key": cacheKey}
			return cached, nil
		}
	}

	blob, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("encode single-wallet request: %w", err)
	}

	result, err := runPythonJSON(
		ctx,
		pythonBin,
		pythonRoot,
		[]string{"-c", singleWalletScript},
		[]string{"NESSA_ASC_SINGLE_REQ=" + string(blob)},
	)
	if err != nil {
		return nil, err
	}

	result["cache"] = map[string]any{"hit": false, "key": cacheKey}
	if !opts.DisableCache {
		if err := cache.Add(cacheKey, result); err != nil {
			return nil, err
		}
	}
	return result, nil
}

func buildSingleWalletRequest(opts SingleWalletVerifyOptions, pythonRoot string) map[string]any {
	return map[string]any{
		"python_root":           pythonRoot,
		"user_label":            opts.UserLabel,
		"device_label":          opts.DeviceLabel,
		"wallet_secret_hex":     opts.WalletSecretHex,
		"campaign_id":           opts.CampaignID,
		"verifier_id":           opts.VerifierID,
		"campaign_window":       opts.CampaignWindow,
		"weight_profile":        opts.WeightProfile,
		"pseudonym_scope":       opts.PseudonymScope,
		"required_consent_mask": opts.RequiredConsent,
		"min_age_band":          opts.MinAgeBand,
		"deterministic":         opts.Deterministic,
		"deterministic_secret":  opts.DeterministicSecret,
		"target_rows":           opts.TargetRows,
		"include_raw_bundle":    opts.IncludeRawBundle,
		"metadata": map[string]any{
			"age_band":         opts.Metadata.AgeBand,
			"interest_code":    opts.Metadata.InterestCode,
			"location_tier":    opts.Metadata.LocationTier,
			"device_class":     opts.Metadata.DeviceClass,
			"browsing_segment": opts.Metadata.BrowsingSegment,
			"income_bracket":   opts.Metadata.IncomeBracket,
			"engagement_level": opts.Metadata.EngagementLevel,
			"consent_flags":    opts.Metadata.ConsentFlags,
		},
	}
}

func deriveSingleWalletCacheKey(req map[string]any) (string, error) {
	copyReq := map[string]any{}
	for k, v := range req {
		if k == "python_root" || k == "include_raw_bundle" {
			continue
		}
		copyReq[k] = v
	}
	blob, err := json.Marshal(copyReq)
	if err != nil {
		return "", fmt.Errorf("encode cache key payload: %w", err)
	}
	digest := sha256.Sum256(blob)
	return hex.EncodeToString(digest[:]), nil
}
