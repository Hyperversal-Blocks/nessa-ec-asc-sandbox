package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Hyperversal-Blocks/nessa-ec/nessa-go/pkg/asc"
)

func main() {
	if len(os.Args) < 2 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch os.Args[1] {
	case "asc-e2e":
		if err := runASCE2E(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "asc-user":
		if err := runASCUser(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "asc-api":
		if err := runASCAPI(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
	case "help", "-h", "--help":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		usage(os.Stderr)
		os.Exit(2)
	}
}

func runASCAPI(args []string) error {
	fs := flag.NewFlagSet("asc-api", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	addr := fs.String("addr", ":8090", "listen address")
	pythonRoot := fs.String("python-root", "", "path to nessa-paper root containing app.py")
	pythonBin := fs.String("python-bin", "", "python executable (default: NESSA_PYTHON_BIN or python3)")
	artifactsDir := fs.String("artifacts-dir", "", "directory for API flow artifacts (default: <python-root>/docs/generated/asc_api_demo)")
	metadataCacheSize := fs.Int("metadata-cache-size", 512, "in-memory metadata cache size")

	if err := fs.Parse(args); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Fprintf(os.Stdout, "starting ASC API server on %s\n", *addr)
	return asc.ServeAPI(ctx, asc.APIServerOptions{
		Addr:              *addr,
		PythonRoot:        *pythonRoot,
		PythonBinary:      *pythonBin,
		ArtifactsDir:      *artifactsDir,
		MetadataCacheSize: *metadataCacheSize,
	})
}

func usage(out *os.File) {
	fmt.Fprintln(out, "nessa-go")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  nessa asc-e2e [flags]")
	fmt.Fprintln(out, "  nessa asc-user [flags]")
	fmt.Fprintln(out, "  nessa asc-api [flags]")
	fmt.Fprintln(out, "")
	fmt.Fprintln(out, "Commands:")
	fmt.Fprintln(out, "  asc-e2e    Run ASC end-to-end flow via Python core")
	fmt.Fprintln(out, "  asc-user   Run single-wallet/single-campaign prove+verify")
	fmt.Fprintln(out, "  asc-api    Run chi HTTP API server for multi-user/multi-verifier flows")
}

func runASCE2E(args []string) error {
	fs := flag.NewFlagSet("asc-e2e", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	deterministic := fs.Bool("deterministic", false, "run deterministic ASC flow")
	benchmark := fs.Bool("benchmark", false, "include benchmark output")
	rootArtifacts := fs.Bool("root-artifacts", false, "write root artifacts in Python repo docs tree")

	artifactsDir := fs.String("artifacts-dir", "", "override artifacts output directory")
	reportPath := fs.String("report", "", "report output directory or prefix")
	pythonRoot := fs.String("python-root", "", "path to nessa-paper root containing app.py")
	pythonBin := fs.String("python-bin", "", "python executable to run (default: NESSA_PYTHON_BIN or python3)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	result, err := asc.Run(context.Background(), asc.RunOptions{
		Deterministic: *deterministic,
		Benchmark:     *benchmark,
		RootArtifacts: *rootArtifacts,
		ArtifactsDir:  *artifactsDir,
		ReportPath:    *reportPath,
		PythonBinary:  *pythonBin,
		PythonRoot:    *pythonRoot,
	})
	if err != nil {
		return err
	}

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal asc output: %w", err)
	}
	fmt.Fprintln(os.Stdout, string(out))
	return nil
}

func runASCUser(args []string) error {
	fs := flag.NewFlagSet("asc-user", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	jsonOut := fs.Bool("json", false, "emit full JSON output")
	includeRawBundle := fs.Bool("include-raw-bundle", false, "include unredacted bundle in JSON output")
	noCache := fs.Bool("no-cache", false, "disable in-memory cache for this command")
	repeat := fs.Int("repeat", 1, "number of repeated runs in one process (demonstrates cache hits)")

	userLabel := fs.String("user-label", "user://default", "user label")
	deviceLabel := fs.String("device-label", "device://phone", "device label")

	campaignID := fs.String("campaign-id", "campaign://luxury-targeting", "campaign id")
	verifierID := fs.String("verifier-id", "verifier://ads-harvester", "verifier id")
	campaignWindow := fs.String("campaign-window", "window:2026-q1", "campaign window")
	weightProfile := fs.String("weight-profile", "luxury_targeting", "campaign weight profile")
	pseudonymScope := fs.String("pseudonym-scope", "per_verifier", "pseudonym scope")
	requiredConsent := fs.Int("required-consent-mask", 0, "required consent bitmask")
	minAgeBand := fs.Int("min-age-band", 0, "minimum age band")

	ageBand := fs.Int("age-band", 8, "metadata age_band")
	interestCode := fs.Int("interest-code", 1001, "metadata interest_code")
	locationTier := fs.Int("location-tier", 3, "metadata location_tier")
	deviceClass := fs.Int("device-class", 1, "metadata device_class")
	browsingSegment := fs.Int("browsing-segment", 7, "metadata browsing_segment")
	incomeBracket := fs.Int("income-bracket", 10, "metadata income_bracket")
	engagementLevel := fs.Int("engagement-level", 85, "metadata engagement_level")
	consentFlags := fs.Int("consent-flags", 15, "metadata consent_flags")

	deterministic := fs.Bool("deterministic", true, "use deterministic proving seed")
	deterministicSecret := fs.Bool("deterministic-secret", true, "derive deterministic wallet secret")
	targetRows := fs.Int("target-rows", 0, "optional explicit row count (0 keeps default weighted rows)")

	pythonRoot := fs.String("python-root", "", "path to nessa-paper root containing app.py")
	pythonBin := fs.String("python-bin", "", "python executable (default: NESSA_PYTHON_BIN or python3)")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *repeat < 1 {
		return fmt.Errorf("repeat must be >= 1")
	}

	options := asc.SingleWalletVerifyOptions{
		UserLabel:       *userLabel,
		DeviceLabel:     *deviceLabel,
		CampaignID:      *campaignID,
		VerifierID:      *verifierID,
		CampaignWindow:  *campaignWindow,
		WeightProfile:   *weightProfile,
		PseudonymScope:  *pseudonymScope,
		RequiredConsent: *requiredConsent,
		MinAgeBand:      *minAgeBand,
		Metadata: asc.MetadataProfile{
			AgeBand:         *ageBand,
			InterestCode:    *interestCode,
			LocationTier:    *locationTier,
			DeviceClass:     *deviceClass,
			BrowsingSegment: *browsingSegment,
			IncomeBracket:   *incomeBracket,
			EngagementLevel: *engagementLevel,
			ConsentFlags:    *consentFlags,
		},
		Deterministic:       *deterministic,
		DeterministicSecret: *deterministicSecret,
		TargetRows:          *targetRows,
		IncludeRawBundle:    *includeRawBundle,
		DisableCache:        *noCache,
		PythonBinary:        *pythonBin,
		PythonRoot:          *pythonRoot,
	}

	cacheHitCount := 0
	var result map[string]any
	for i := 0; i < *repeat; i++ {
		var err error
		result, err = asc.RunSingleWalletVerify(context.Background(), options)
		if err != nil {
			return err
		}
		if cache, ok := result["cache"].(map[string]any); ok {
			if hit, _ := cache["hit"].(bool); hit {
				cacheHitCount++
			}
		}
	}
	result["run_count"] = *repeat
	result["cache_hit_count"] = cacheHitCount

	out, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal asc-user output: %w", err)
	}
	if *jsonOut {
		fmt.Fprintln(os.Stdout, string(out))
		return nil
	}

	receipt, _ := result["verification_receipt"].(map[string]any)
	cache, _ := result["cache"].(map[string]any)
	campaign, _ := result["campaign"].(map[string]any)

	accepted, _ := receipt["accepted"].(bool)
	proofValid, _ := receipt["proof_valid"].(bool)
	eligibilityValid, _ := receipt["eligibility_valid"].(bool)
	verifyMS, _ := receipt["verify_ms"].(float64)
	proofSize, _ := receipt["proof_size_bytes"].(float64)
	cacheHit, _ := cache["hit"].(bool)

	reasonCodes := []string{}
	if rawReasons, ok := receipt["reason_codes"].([]any); ok {
		for _, item := range rawReasons {
			reasonCodes = append(reasonCodes, fmt.Sprint(item))
		}
	}

	fmt.Fprintln(os.Stdout, "ASC single-wallet prove+verify complete")
	fmt.Fprintf(os.Stdout, "  runs=%d cache_hit_count=%d\n", *repeat, cacheHitCount)
	fmt.Fprintf(os.Stdout, "  campaign=%v accepted=%v cache_hit=%v\n", campaign["campaign_id"], accepted, cacheHit)
	fmt.Fprintf(os.Stdout, "  proof_valid=%v eligibility_valid=%v verify_ms=%.3f proof_size_bytes=%d\n", proofValid, eligibilityValid, verifyMS, int64(proofSize))
	if len(reasonCodes) > 0 {
		fmt.Fprintf(os.Stdout, "  reasons=%s\n", strings.Join(reasonCodes, ","))
	}
	return nil
}
