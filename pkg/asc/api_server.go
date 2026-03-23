package asc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	lru "github.com/hashicorp/golang-lru/v2"
)

// APIServerOptions configures the ASC API server.
type APIServerOptions struct {
	Addr              string
	PythonRoot        string
	PythonBinary      string
	ArtifactsDir      string
	MetadataCacheSize int
}

type ascAPI struct {
	pythonRoot   string
	pythonBin    string
	artifactsDir string

	walletMu sync.RWMutex
	wallets  map[string]*walletRecord

	metadataMu    sync.RWMutex
	metadataCache *lru.Cache[string, MetadataProfile]

	resultCache ResultCache
	now         func() time.Time
}

type walletRecord struct {
	WalletID      string
	UserLabel     string
	DeviceLabel   string
	PrivateKeyHex string
	PublicKeyHex  string
	Metadata      *MetadataProfile
	CreatedAt     time.Time
}

type walletSnapshot struct {
	WalletID      string
	UserLabel     string
	DeviceLabel   string
	PrivateKeyHex string
	PublicKeyHex  string
	Metadata      MetadataProfile
}

type createWalletRequest struct {
	UserLabel     string `json:"user_label"`
	DeviceLabel   string `json:"device_label"`
	PrivateKeyHex string `json:"private_key_hex"`
}

type updateMetadataRequest struct {
	AgeBand         int `json:"age_band"`
	InterestCode    int `json:"interest_code"`
	LocationTier    int `json:"location_tier"`
	DeviceClass     int `json:"device_class"`
	BrowsingSegment int `json:"browsing_segment"`
	IncomeBracket   int `json:"income_bracket"`
	EngagementLevel int `json:"engagement_level"`
	ConsentFlags    int `json:"consent_flags"`
}

type campaignConfig struct {
	CampaignID      string `json:"campaign_id"`
	VerifierID      string `json:"verifier_id"`
	CampaignWindow  string `json:"campaign_window"`
	WeightProfile   string `json:"weight_profile"`
	PseudonymScope  string `json:"pseudonym_scope"`
	RequiredConsent int    `json:"required_consent_mask"`
	MinAgeBand      int    `json:"min_age_band"`
}

type selectiveDisclosureRequest struct {
	Fields []string `json:"fields"`
}

type verifierCentricFlowRequest struct {
	WalletIDs           []string                   `json:"wallet_ids"`
	Campaign            campaignConfig             `json:"campaign"`
	Deterministic       bool                       `json:"deterministic"`
	TargetRows          int                        `json:"target_rows"`
	SelectiveDisclosure selectiveDisclosureRequest `json:"selective_disclosure"`
}

type userCentricFlowRequest struct {
	WalletID            string                     `json:"wallet_id"`
	Verifiers           []campaignConfig           `json:"verifiers"`
	Deterministic       bool                       `json:"deterministic"`
	TargetRows          int                        `json:"target_rows"`
	SelectiveDisclosure selectiveDisclosureRequest `json:"selective_disclosure"`
}

type benchmarkRequest struct {
	Mode          string `json:"mode"`
	Sizes         []int  `json:"sizes"`
	Deterministic bool   `json:"deterministic"`
	TargetRows    int    `json:"target_rows"`
}

type stressRequest struct {
	Mode          string `json:"mode"`
	Concurrency   int    `json:"concurrency"`
	Iterations    int    `json:"iterations"`
	UserCount     int    `json:"user_count"`
	VerifierCount int    `json:"verifier_count"`
	Deterministic bool   `json:"deterministic"`
	TargetRows    int    `json:"target_rows"`
}

type apiError struct {
	Error string `json:"error"`
}

// ServeAPI starts the ASC HTTP API server.
func ServeAPI(ctx context.Context, opts APIServerOptions) error {
	pythonRoot, err := resolvePythonRoot(opts.PythonRoot)
	if err != nil {
		return err
	}
	pythonBin := resolvePythonBin(opts.PythonBinary)

	cacheSize := opts.MetadataCacheSize
	if cacheSize < 1 {
		cacheSize = 512
	}
	metadataCache, err := lru.New[string, MetadataProfile](cacheSize)
	if err != nil {
		return fmt.Errorf("init metadata cache: %w", err)
	}
	resultCache, err := NewLRUResultCache(1024)
	if err != nil {
		return err
	}

	artifactsDir := opts.ArtifactsDir
	if artifactsDir == "" {
		artifactsDir = filepath.Join(pythonRoot, "docs", "generated", "asc_api_demo")
	}

	addr := opts.Addr
	if addr == "" {
		addr = ":8090"
	}

	api := &ascAPI{
		pythonRoot:    pythonRoot,
		pythonBin:     pythonBin,
		artifactsDir:  artifactsDir,
		wallets:       make(map[string]*walletRecord),
		metadataCache: metadataCache,
		resultCache:   resultCache,
		now:           time.Now,
	}

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.Recoverer)
	r.Use(middleware.Timeout(2 * time.Minute))
	api.registerRoutes(r)

	srv := &http.Server{Addr: addr, Handler: r}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	err = srv.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (a *ascAPI) registerRoutes(r chi.Router) {
	r.Get("/healthz", a.handleHealth)
	r.Route("/api/v1", func(r chi.Router) {
		r.Post("/wallets", a.handleCreateWallet)
		r.Get("/wallets/{walletID}", a.handleGetWallet)
		r.Put("/wallets/{walletID}/metadata", a.handleUpdateWalletMetadata)
		r.Post("/flows/verifier-centric", a.handleVerifierCentricFlow)
		r.Post("/flows/user-centric", a.handleUserCentricFlow)
		r.Post("/benchmarks", a.handleBenchmark)
		r.Post("/stress", a.handleStress)
		r.Get("/references/go-migration", a.handleGoMigrationReferences)
	})
}

func (a *ascAPI) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "ok",
		"service":       "nessa-asc-api",
		"python_root":   a.pythonRoot,
		"artifacts_dir": a.artifactsDir,
	})
}

func (a *ascAPI) handleCreateWallet(w http.ResponseWriter, r *http.Request) {
	var req createWalletRequest
	if !decodeJSON(w, r, &req) {
		return
	}

	priv, pub, err := parseOrGeneratePrivateKey(req.PrivateKeyHex)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	walletID := randomLabel("wallet")
	userLabel := req.UserLabel
	if userLabel == "" {
		userLabel = "user://" + walletID
	}
	deviceLabel := req.DeviceLabel
	if deviceLabel == "" {
		deviceLabel = "device://default"
	}

	rec := &walletRecord{
		WalletID:      walletID,
		UserLabel:     userLabel,
		DeviceLabel:   deviceLabel,
		PrivateKeyHex: hex.EncodeToString(priv),
		PublicKeyHex:  hex.EncodeToString(pub),
		CreatedAt:     a.now().UTC(),
	}

	a.walletMu.Lock()
	a.wallets[walletID] = rec
	a.walletMu.Unlock()

	writeJSON(w, http.StatusCreated, map[string]any{
		"wallet_id":       rec.WalletID,
		"user_label":      rec.UserLabel,
		"device_label":    rec.DeviceLabel,
		"public_key_hex":  rec.PublicKeyHex,
		"private_key_hex": rec.PrivateKeyHex,
		"created_at":      rec.CreatedAt.Format(time.RFC3339),
	})
}

func (a *ascAPI) handleGetWallet(w http.ResponseWriter, r *http.Request) {
	walletID := chi.URLParam(r, "walletID")
	a.walletMu.RLock()
	rec, ok := a.wallets[walletID]
	a.walletMu.RUnlock()
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("wallet not found: %s", walletID))
		return
	}

	hasMetadata := rec.Metadata != nil
	writeJSON(w, http.StatusOK, map[string]any{
		"wallet_id":      rec.WalletID,
		"user_label":     rec.UserLabel,
		"device_label":   rec.DeviceLabel,
		"public_key_hex": rec.PublicKeyHex,
		"has_metadata":   hasMetadata,
		"created_at":     rec.CreatedAt.Format(time.RFC3339),
	})
}

func (a *ascAPI) handleUpdateWalletMetadata(w http.ResponseWriter, r *http.Request) {
	walletID := chi.URLParam(r, "walletID")
	metaReq := updateMetadataRequest{}
	if !decodeJSON(w, r, &metaReq) {
		return
	}

	meta := MetadataProfile{
		AgeBand:         metaReq.AgeBand,
		InterestCode:    metaReq.InterestCode,
		LocationTier:    metaReq.LocationTier,
		DeviceClass:     metaReq.DeviceClass,
		BrowsingSegment: metaReq.BrowsingSegment,
		IncomeBracket:   metaReq.IncomeBracket,
		EngagementLevel: metaReq.EngagementLevel,
		ConsentFlags:    metaReq.ConsentFlags,
	}

	a.walletMu.Lock()
	rec, ok := a.wallets[walletID]
	if ok {
		m := meta
		rec.Metadata = &m
	}
	a.walletMu.Unlock()
	if !ok {
		writeError(w, http.StatusNotFound, fmt.Errorf("wallet not found: %s", walletID))
		return
	}

	a.metadataMu.Lock()
	a.metadataCache.Add(walletID, meta)
	a.metadataMu.Unlock()

	writeJSON(w, http.StatusOK, map[string]any{
		"wallet_id": walletID,
		"metadata":  meta,
	})
}

func (a *ascAPI) handleVerifierCentricFlow(w http.ResponseWriter, r *http.Request) {
	req := verifierCentricFlowRequest{Deterministic: true}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.WalletIDs) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("wallet_ids must not be empty"))
		return
	}

	campaign := req.Campaign.withDefaults()
	if err := campaign.validate(); err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	started := a.now()
	accepted := 0
	results := make([]map[string]any, 0, len(req.WalletIDs))
	for _, walletID := range req.WalletIDs {
		snap, err := a.loadWalletSnapshot(walletID)
		if err != nil {
			results = append(results, map[string]any{"wallet_id": walletID, "error": err.Error()})
			continue
		}
		flowResult, ok, err := a.runSingleWalletFlow(r.Context(), snap, campaign, req.Deterministic, req.TargetRows)
		if err != nil {
			results = append(results, map[string]any{"wallet_id": walletID, "error": err.Error()})
			continue
		}
		if ok {
			accepted++
		}
		results = append(results, map[string]any{
			"wallet_id": walletID,
			"accepted":  ok,
			"result":    applySelectiveDisclosure(flowResult, req.SelectiveDisclosure.Fields),
		})
	}

	response := map[string]any{
		"mode":           "verifier_centric_multi_user",
		"verifier_id":    campaign.VerifierID,
		"campaign_id":    campaign.CampaignID,
		"user_count":     len(req.WalletIDs),
		"accepted_count": accepted,
		"rejected_count": len(req.WalletIDs) - accepted,
		"elapsed_ms":     millisSince(started, a.now()),
		"results":        results,
	}
	a.attachArtifact(response, "verifier_centric")
	writeJSON(w, http.StatusOK, response)
}

func (a *ascAPI) handleUserCentricFlow(w http.ResponseWriter, r *http.Request) {
	req := userCentricFlowRequest{Deterministic: true}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.WalletID == "" {
		writeError(w, http.StatusBadRequest, errors.New("wallet_id is required"))
		return
	}
	if len(req.Verifiers) == 0 {
		writeError(w, http.StatusBadRequest, errors.New("verifiers must not be empty"))
		return
	}

	snap, err := a.loadWalletSnapshot(req.WalletID)
	if err != nil {
		writeError(w, http.StatusBadRequest, err)
		return
	}

	started := a.now()
	accepted := 0
	results := make([]map[string]any, 0, len(req.Verifiers))
	for i, verifierCampaign := range req.Verifiers {
		campaign := verifierCampaign.withDefaults()
		if campaign.CampaignID == "" {
			campaign.CampaignID = fmt.Sprintf("campaign://multi-verifier-%d", i+1)
		}
		if err := campaign.validate(); err != nil {
			results = append(results, map[string]any{
				"index": i,
				"error": err.Error(),
			})
			continue
		}

		flowResult, ok, err := a.runSingleWalletFlow(r.Context(), snap, campaign, req.Deterministic, req.TargetRows)
		if err != nil {
			results = append(results, map[string]any{
				"index":       i,
				"verifier_id": campaign.VerifierID,
				"campaign_id": campaign.CampaignID,
				"error":       err.Error(),
			})
			continue
		}
		if ok {
			accepted++
		}
		results = append(results, map[string]any{
			"index":       i,
			"verifier_id": campaign.VerifierID,
			"campaign_id": campaign.CampaignID,
			"accepted":    ok,
			"result":      applySelectiveDisclosure(flowResult, req.SelectiveDisclosure.Fields),
		})
	}

	response := map[string]any{
		"mode":           "user_centric_multi_verifier",
		"wallet_id":      req.WalletID,
		"verifier_count": len(req.Verifiers),
		"accepted_count": accepted,
		"rejected_count": len(req.Verifiers) - accepted,
		"elapsed_ms":     millisSince(started, a.now()),
		"results":        results,
	}
	a.attachArtifact(response, "user_centric")
	writeJSON(w, http.StatusOK, response)
}

func (a *ascAPI) handleBenchmark(w http.ResponseWriter, r *http.Request) {
	req := benchmarkRequest{Mode: "verifier_centric", Deterministic: true, Sizes: []int{8, 16, 32}}
	if !decodeJSON(w, r, &req) {
		return
	}
	if len(req.Sizes) == 0 {
		req.Sizes = []int{8, 16, 32}
	}
	sort.Ints(req.Sizes)

	rows := make([]map[string]any, 0, len(req.Sizes))
	for _, n := range req.Sizes {
		if n < 1 {
			continue
		}
		row, err := a.runBenchmarkRow(r.Context(), req.Mode, n, req.Deterministic, req.TargetRows)
		if err != nil {
			rows = append(rows, map[string]any{"N": n, "error": err.Error()})
			continue
		}
		rows = append(rows, row)
	}

	response := map[string]any{
		"mode":          req.Mode,
		"sizes":         req.Sizes,
		"rows":          rows,
		"deterministic": req.Deterministic,
	}
	a.attachArtifact(response, "benchmark_"+sanitizeLabel(req.Mode))
	writeJSON(w, http.StatusOK, response)
}

func (a *ascAPI) handleStress(w http.ResponseWriter, r *http.Request) {
	req := stressRequest{
		Mode:          "verifier_centric",
		Concurrency:   runtime.NumCPU(),
		Iterations:    20,
		UserCount:     8,
		VerifierCount: 8,
		Deterministic: true,
	}
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.Concurrency < 1 {
		req.Concurrency = 1
	}
	if req.Iterations < 1 {
		req.Iterations = 1
	}
	if req.UserCount < 1 {
		req.UserCount = 1
	}
	if req.VerifierCount < 1 {
		req.VerifierCount = 1
	}

	taskCount, runTask := a.buildStressPlan(req)
	if taskCount < 1 {
		writeError(w, http.StatusBadRequest, fmt.Errorf("unsupported stress mode: %s", req.Mode))
		return
	}

	started := a.now()
	jobs := make(chan int)
	var success atomic.Int64
	var failure atomic.Int64
	var totalMS atomic.Int64
	var maxMS atomic.Int64

	var wg sync.WaitGroup
	for i := 0; i < req.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range jobs {
				t0 := time.Now()
				err := runTask(r.Context())
				elapsedMS := time.Since(t0).Milliseconds()
				totalMS.Add(elapsedMS)
				for {
					prev := maxMS.Load()
					if elapsedMS <= prev || maxMS.CompareAndSwap(prev, elapsedMS) {
						break
					}
				}
				if err != nil {
					failure.Add(1)
					continue
				}
				success.Add(1)
			}
		}()
	}

	for i := 0; i < taskCount; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()

	elapsedSeconds := a.now().Sub(started).Seconds()
	if elapsedSeconds <= 0 {
		elapsedSeconds = 0.001
	}
	response := map[string]any{
		"mode":                 req.Mode,
		"task_count":           taskCount,
		"concurrency":          req.Concurrency,
		"iterations":           req.Iterations,
		"success_count":        success.Load(),
		"failure_count":        failure.Load(),
		"elapsed_ms":           millisSince(started, a.now()),
		"throughput_per_sec":   float64(taskCount) / elapsedSeconds,
		"avg_task_ms":          float64(totalMS.Load()) / float64(taskCount),
		"max_task_ms":          maxMS.Load(),
		"deterministic":        req.Deterministic,
		"stress_configuration": req,
	}
	a.attachArtifact(response, "stress_"+sanitizeLabel(req.Mode))
	writeJSON(w, http.StatusOK, response)
}

func (a *ascAPI) handleGoMigrationReferences(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"title": "Go migration references",
		"libraries": []map[string]any{
			{
				"name":    "go-chi/chi",
				"url":     "https://github.com/go-chi/chi",
				"use_for": []string{"HTTP routing", "middleware", "route composition"},
			},
			{
				"name":    "crypto/ed25519",
				"url":     "https://pkg.go.dev/crypto/ed25519",
				"use_for": []string{"wallet key management", "request signing", "public key identities"},
			},
			{
				"name":    "hashicorp/golang-lru/v2",
				"url":     "https://github.com/hashicorp/golang-lru",
				"use_for": []string{"metadata/result caching", "bounded memory usage"},
			},
			{
				"name":    "fxamacker/cbor/v2",
				"url":     "https://github.com/fxamacker/cbor",
				"use_for": []string{"deterministic CBOR encoding", "wire-format parity"},
			},
			{
				"name":    "gtank/ristretto255",
				"url":     "https://github.com/gtank/ristretto255",
				"use_for": []string{"Ristretto255 operations", "future protocol parity work"},
			},
		},
		"migration_notes": []string{
			"Keep API contract stable while replacing Python subprocess calls endpoint-by-endpoint.",
			"Move deterministic transcript assembly first, then proof generation, then verification.",
			"Maintain cross-language test vectors for each migration milestone.",
		},
	})
}

func (a *ascAPI) runBenchmarkRow(ctx context.Context, mode string, n int, deterministic bool, targetRows int) (map[string]any, error) {
	start := a.now()
	accepted := 0
	runs := 0

	switch normalizeMode(mode) {
	case "verifier_centric":
		campaign := campaignConfig{
			CampaignID:     fmt.Sprintf("campaign://bench-vc-%d", n),
			VerifierID:     "verifier://benchmark-vc",
			CampaignWindow: "window:benchmark",
			WeightProfile:  "broad_reach",
		}.withDefaults()
		for i := 0; i < n; i++ {
			snap := syntheticWallet(fmt.Sprintf("vc:%d", i), i)
			_, ok, err := a.runSingleWalletFlow(ctx, snap, campaign, deterministic, targetRows)
			if err != nil {
				return nil, err
			}
			runs++
			if ok {
				accepted++
			}
		}
	case "user_centric":
		snap := syntheticWallet(fmt.Sprintf("uc:%d", n), n)
		for i := 0; i < n; i++ {
			campaign := campaignConfig{
				CampaignID:     fmt.Sprintf("campaign://bench-uc-%d", i),
				VerifierID:     fmt.Sprintf("verifier://benchmark-%d", i),
				CampaignWindow: "window:benchmark",
				WeightProfile:  "broad_reach",
			}.withDefaults()
			_, ok, err := a.runSingleWalletFlow(ctx, snap, campaign, deterministic, targetRows)
			if err != nil {
				return nil, err
			}
			runs++
			if ok {
				accepted++
			}
		}
	default:
		return nil, fmt.Errorf("unsupported benchmark mode: %s", mode)
	}

	elapsed := millisSince(start, a.now())
	throughput := 0.0
	if elapsed > 0 {
		throughput = float64(runs) / (elapsed / 1000.0)
	}
	return map[string]any{
		"N":                  n,
		"mode":               normalizeMode(mode),
		"runs":               runs,
		"accepted_count":     accepted,
		"rejected_count":     runs - accepted,
		"elapsed_ms":         elapsed,
		"throughput_per_sec": throughput,
	}, nil
}

func (a *ascAPI) buildStressPlan(req stressRequest) (int, func(context.Context) error) {
	mode := normalizeMode(req.Mode)
	switch mode {
	case "verifier_centric":
		campaign := campaignConfig{
			CampaignID:     "campaign://stress-vc",
			VerifierID:     "verifier://stress-vc",
			CampaignWindow: "window:stress",
			WeightProfile:  "broad_reach",
		}.withDefaults()
		wallets := make([]walletSnapshot, 0, req.UserCount)
		for i := 0; i < req.UserCount; i++ {
			wallets = append(wallets, syntheticWallet(fmt.Sprintf("stress-vc:%d", i), i))
		}
		var idx atomic.Int64
		totalTasks := req.Iterations * len(wallets)
		run := func(ctx context.Context) error {
			position := int(idx.Add(1)-1) % len(wallets)
			_, _, err := a.runSingleWalletFlow(ctx, wallets[position], campaign, req.Deterministic, req.TargetRows)
			return err
		}
		return totalTasks, run
	case "user_centric":
		wallet := syntheticWallet("stress-uc", 1)
		verifiers := make([]campaignConfig, 0, req.VerifierCount)
		for i := 0; i < req.VerifierCount; i++ {
			verifiers = append(verifiers, campaignConfig{
				CampaignID:     fmt.Sprintf("campaign://stress-uc-%d", i),
				VerifierID:     fmt.Sprintf("verifier://stress-uc-%d", i),
				CampaignWindow: "window:stress",
				WeightProfile:  "broad_reach",
			}.withDefaults())
		}
		var idx atomic.Int64
		totalTasks := req.Iterations * len(verifiers)
		run := func(ctx context.Context) error {
			position := int(idx.Add(1)-1) % len(verifiers)
			_, _, err := a.runSingleWalletFlow(ctx, wallet, verifiers[position], req.Deterministic, req.TargetRows)
			return err
		}
		return totalTasks, run
	default:
		return 0, nil
	}
}

func (a *ascAPI) runSingleWalletFlow(ctx context.Context, snap walletSnapshot, campaign campaignConfig, deterministic bool, targetRows int) (map[string]any, bool, error) {
	walletSecretHex, err := deriveWalletSecretHexFromPrivateHex(snap.PrivateKeyHex)
	if err != nil {
		return nil, false, err
	}

	result, err := RunSingleWalletVerify(ctx, SingleWalletVerifyOptions{
		UserLabel:       snap.UserLabel,
		DeviceLabel:     snap.DeviceLabel,
		CampaignID:      campaign.CampaignID,
		VerifierID:      campaign.VerifierID,
		CampaignWindow:  campaign.CampaignWindow,
		WeightProfile:   campaign.WeightProfile,
		PseudonymScope:  campaign.PseudonymScope,
		RequiredConsent: campaign.RequiredConsent,
		MinAgeBand:      campaign.MinAgeBand,
		Metadata:        snap.Metadata,
		Deterministic:   deterministic,
		TargetRows:      targetRows,
		WalletSecretHex: walletSecretHex,
		Cache:           a.resultCache,
		PythonBinary:    a.pythonBin,
		PythonRoot:      a.pythonRoot,
	})
	if err != nil {
		return nil, false, err
	}

	accepted := false
	if receipt, ok := result["verification_receipt"].(map[string]any); ok {
		accepted, _ = receipt["accepted"].(bool)
	}
	return result, accepted, nil
}

func (a *ascAPI) loadWalletSnapshot(walletID string) (walletSnapshot, error) {
	a.walletMu.RLock()
	rec, ok := a.wallets[walletID]
	a.walletMu.RUnlock()
	if !ok {
		return walletSnapshot{}, fmt.Errorf("wallet not found: %s", walletID)
	}

	meta, ok := a.getCachedMetadata(walletID)
	if !ok {
		if rec.Metadata == nil {
			return walletSnapshot{}, fmt.Errorf("metadata not set for wallet: %s", walletID)
		}
		meta = *rec.Metadata
		a.metadataMu.Lock()
		a.metadataCache.Add(walletID, meta)
		a.metadataMu.Unlock()
	}

	return walletSnapshot{
		WalletID:      rec.WalletID,
		UserLabel:     rec.UserLabel,
		DeviceLabel:   rec.DeviceLabel,
		PrivateKeyHex: rec.PrivateKeyHex,
		PublicKeyHex:  rec.PublicKeyHex,
		Metadata:      meta,
	}, nil
}

func (a *ascAPI) getCachedMetadata(walletID string) (MetadataProfile, bool) {
	a.metadataMu.RLock()
	defer a.metadataMu.RUnlock()
	meta, ok := a.metadataCache.Get(walletID)
	return meta, ok
}

func (a *ascAPI) attachArtifact(response map[string]any, prefix string) {
	path, err := a.writeArtifact(prefix, response)
	if err != nil {
		response["artifact_error"] = err.Error()
		return
	}
	response["artifact_file"] = path
}

func (a *ascAPI) writeArtifact(prefix string, payload any) (string, error) {
	if err := os.MkdirAll(a.artifactsDir, 0o755); err != nil {
		return "", fmt.Errorf("create artifacts dir: %w", err)
	}
	name := fmt.Sprintf("%s_%s.json", sanitizeLabel(prefix), a.now().UTC().Format("20060102T150405Z"))
	path := filepath.Join(a.artifactsDir, name)
	blob, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode artifact: %w", err)
	}
	if err := os.WriteFile(path, blob, 0o644); err != nil {
		return "", fmt.Errorf("write artifact file: %w", err)
	}
	return path, nil
}

func (c campaignConfig) withDefaults() campaignConfig {
	if c.CampaignWindow == "" {
		c.CampaignWindow = "window:2026-q1"
	}
	if c.WeightProfile == "" {
		c.WeightProfile = "luxury_targeting"
	}
	if c.PseudonymScope == "" {
		c.PseudonymScope = "per_verifier"
	}
	return c
}

func (c campaignConfig) validate() error {
	if c.CampaignID == "" {
		return errors.New("campaign_id is required")
	}
	if c.VerifierID == "" {
		return errors.New("verifier_id is required")
	}
	return nil
}

func syntheticWallet(seedLabel string, index int) walletSnapshot {
	digest := sha256.Sum256([]byte("nessa-asc-wallet:" + seedLabel))
	priv := ed25519.NewKeyFromSeed(digest[:])
	pub := priv.Public().(ed25519.PublicKey)
	return walletSnapshot{
		WalletID:      "wallet://" + hex.EncodeToString(digest[:6]),
		UserLabel:     "user://" + sanitizeLabel(seedLabel),
		DeviceLabel:   "device://bench",
		PrivateKeyHex: hex.EncodeToString(priv),
		PublicKeyHex:  hex.EncodeToString(pub),
		Metadata:      syntheticMetadata(index),
	}
}

func syntheticMetadata(index int) MetadataProfile {
	return MetadataProfile{
		AgeBand:         2 + (index % 10),
		InterestCode:    1000 + (index % 256),
		LocationTier:    index % 8,
		DeviceClass:     index % 4,
		BrowsingSegment: 5 + (index % 20),
		IncomeBracket:   1 + (index % 12),
		EngagementLevel: 40 + (index % 60),
		ConsentFlags:    0x0F,
	}
}

func parseOrGeneratePrivateKey(privateKeyHex string) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	if strings.TrimSpace(privateKeyHex) == "" {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, nil, fmt.Errorf("generate private key: %w", err)
		}
		return priv, pub, nil
	}

	blob, err := hex.DecodeString(strings.TrimSpace(privateKeyHex))
	if err != nil {
		return nil, nil, fmt.Errorf("decode private_key_hex: %w", err)
	}
	switch len(blob) {
	case ed25519.SeedSize:
		priv := ed25519.NewKeyFromSeed(blob)
		pub := priv.Public().(ed25519.PublicKey)
		return priv, pub, nil
	case ed25519.PrivateKeySize:
		priv := ed25519.PrivateKey(blob)
		pub := priv.Public().(ed25519.PublicKey)
		return priv, pub, nil
	default:
		return nil, nil, fmt.Errorf("private_key_hex must be %d-byte seed or %d-byte private key", ed25519.SeedSize, ed25519.PrivateKeySize)
	}
}

func deriveWalletSecretHexFromPrivateHex(privateKeyHex string) (string, error) {
	priv, _, err := parseOrGeneratePrivateKey(privateKeyHex)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(append([]byte("NESSA-ASC:wallet-secret:v1"), priv...))
	return hex.EncodeToString(digest[:]), nil
}

func applySelectiveDisclosure(input map[string]any, fields []string) map[string]any {
	if len(fields) == 0 {
		return deepCopyMap(input)
	}
	unique := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		field = strings.TrimSpace(field)
		if field == "" {
			continue
		}
		unique[field] = struct{}{}
	}
	keys := make([]string, 0, len(unique))
	for field := range unique {
		keys = append(keys, field)
	}
	sort.Strings(keys)

	out := make(map[string]any)
	for _, field := range keys {
		parts := strings.Split(field, ".")
		copyFieldPath(out, input, parts)
	}
	return out
}

func copyFieldPath(dst map[string]any, src map[string]any, path []string) {
	if len(path) == 0 {
		return
	}
	current := any(src)
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return
		}
		next, ok := m[key]
		if !ok {
			return
		}
		current = next
	}

	cursor := dst
	for i := 0; i < len(path)-1; i++ {
		key := path[i]
		next, ok := cursor[key].(map[string]any)
		if !ok {
			next = make(map[string]any)
			cursor[key] = next
		}
		cursor = next
	}
	cursor[path[len(path)-1]] = deepCopyAny(current)
}

func deepCopyMap(input map[string]any) map[string]any {
	if input == nil {
		return nil
	}
	blob, err := json.Marshal(input)
	if err != nil {
		return map[string]any{}
	}
	var out map[string]any
	if err := json.Unmarshal(blob, &out); err != nil {
		return map[string]any{}
	}
	return out
}

func deepCopyAny(v any) any {
	blob, err := json.Marshal(v)
	if err != nil {
		return v
	}
	var out any
	if err := json.Unmarshal(blob, &out); err != nil {
		return v
	}
	return out
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	defer r.Body.Close()
	dec := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, fmt.Errorf("decode request body: %w", err))
		return false
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, errors.New("request body must contain a single JSON object"))
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, apiError{Error: err.Error()})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func randomLabel(prefix string) string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		nowDigest := sha256.Sum256([]byte(time.Now().UTC().Format(time.RFC3339Nano)))
		copy(buf, nowDigest[:8])
	}
	return prefix + "-" + hex.EncodeToString(buf)
}

func millisSince(start, end time.Time) float64 {
	return float64(end.Sub(start).Microseconds()) / 1000.0
}

func normalizeMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	mode = strings.ReplaceAll(mode, "-", "_")
	switch mode {
	case "", "verifier", "verifier_centric", "verifiercentric":
		return "verifier_centric"
	case "user", "user_centric", "usercentric":
		return "user_centric"
	default:
		return mode
	}
}

func sanitizeLabel(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if value == "" {
		return "run"
	}
	replacer := strings.NewReplacer("/", "_", ":", "_", " ", "_", "-", "_")
	value = replacer.Replace(value)
	for strings.Contains(value, "__") {
		value = strings.ReplaceAll(value, "__", "_")
	}
	return strings.Trim(value, "_")
}
