package service

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Resinat/Resin/internal/platform"
)

// ------------------------------------------------------------------
// Export / Import data types
// ------------------------------------------------------------------

const exportVersion = 1

// ExportPlatformEntry is the portable representation of a platform.
type ExportPlatformEntry struct {
	Name                             string   `json:"name"`
	StickyTTL                        string   `json:"sticky_ttl"`
	RegexFilters                     []string `json:"regex_filters"`
	RegionFilters                    []string `json:"region_filters"`
	AllocationPolicy                 string   `json:"allocation_policy"`
	ReverseProxyMissAction           string   `json:"reverse_proxy_miss_action"`
	ReverseProxyEmptyAccountBehavior string   `json:"reverse_proxy_empty_account_behavior"`
	ReverseProxyFixedAccountHeader   string   `json:"reverse_proxy_fixed_account_header"`
}

// ExportSubscriptionEntry is the portable representation of a subscription.
type ExportSubscriptionEntry struct {
	Name                    string `json:"name"`
	SourceType              string `json:"source_type"`
	URL                     string `json:"url"`
	Content                 string `json:"content"`
	UpdateInterval          string `json:"update_interval"`
	Enabled                 bool   `json:"enabled"`
	Ephemeral               bool   `json:"ephemeral"`
	EphemeralNodeEvictDelay string `json:"ephemeral_node_evict_delay"`
}

// ExportPayload is the top-level JSON structure for data export/import.
type ExportPayload struct {
	Version       int                       `json:"version"`
	ExportedAt    string                    `json:"exported_at"`
	Platforms     []ExportPlatformEntry     `json:"platforms"`
	Subscriptions []ExportSubscriptionEntry `json:"subscriptions"`
}

// ImportResult summarises what happened during an import.
type ImportResult struct {
	PlatformsCreated       int      `json:"platforms_created"`
	PlatformsSkipped       int      `json:"platforms_skipped"`
	PlatformsOverwritten   int      `json:"platforms_overwritten"`
	SubscriptionsCreated   int      `json:"subscriptions_created"`
	SubscriptionsSkipped   int      `json:"subscriptions_skipped"`
	SubscriptionsOverwritten int    `json:"subscriptions_overwritten"`
	Errors                 []string `json:"errors"`
}

// ------------------------------------------------------------------
// Export
// ------------------------------------------------------------------

// ExportData builds an ExportPayload containing all user-created platforms
// and all subscriptions.
func (s *ControlPlaneService) ExportData() (*ExportPayload, error) {
	// --- platforms (exclude Default) ---
	platforms, err := s.Engine.ListPlatforms()
	if err != nil {
		return nil, internal("list platforms for export", err)
	}

	exportPlatforms := make([]ExportPlatformEntry, 0, len(platforms))
	for _, p := range platforms {
		if p.ID == platform.DefaultPlatformID {
			continue
		}
		resp := platformToResponse(p)
		exportPlatforms = append(exportPlatforms, ExportPlatformEntry{
			Name:                             resp.Name,
			StickyTTL:                        resp.StickyTTL,
			RegexFilters:                     resp.RegexFilters,
			RegionFilters:                    resp.RegionFilters,
			AllocationPolicy:                 resp.AllocationPolicy,
			ReverseProxyMissAction:           resp.ReverseProxyMissAction,
			ReverseProxyEmptyAccountBehavior: resp.ReverseProxyEmptyAccountBehavior,
			ReverseProxyFixedAccountHeader:   resp.ReverseProxyFixedAccountHeader,
		})
	}

	// --- subscriptions ---
	subs, err := s.ListSubscriptions(nil)
	if err != nil {
		return nil, internal("list subscriptions for export", err)
	}

	exportSubs := make([]ExportSubscriptionEntry, 0, len(subs))
	for _, sub := range subs {
		exportSubs = append(exportSubs, ExportSubscriptionEntry{
			Name:                    sub.Name,
			SourceType:              sub.SourceType,
			URL:                     sub.URL,
			Content:                 sub.Content,
			UpdateInterval:          sub.UpdateInterval,
			Enabled:                 sub.Enabled,
			Ephemeral:               sub.Ephemeral,
			EphemeralNodeEvictDelay: sub.EphemeralNodeEvictDelay,
		})
	}

	return &ExportPayload{
		Version:       exportVersion,
		ExportedAt:    time.Now().UTC().Format(time.RFC3339),
		Platforms:     exportPlatforms,
		Subscriptions: exportSubs,
	}, nil
}

// ------------------------------------------------------------------
// Import
// ------------------------------------------------------------------

// ImportData imports platforms and subscriptions from the given payload.
// strategy must be "skip" (default) or "overwrite".
func (s *ControlPlaneService) ImportData(payload ExportPayload, strategy string) (*ImportResult, error) {
	if strategy == "" {
		strategy = "skip"
	}
	if strategy != "skip" && strategy != "overwrite" {
		return nil, invalidArg("strategy must be 'skip' or 'overwrite'")
	}

	result := &ImportResult{Errors: []string{}}

	// ----- import platforms -----
	s.importPlatforms(payload.Platforms, strategy, result)

	// ----- import subscriptions -----
	s.importSubscriptions(payload.Subscriptions, strategy, result)

	return result, nil
}

func (s *ControlPlaneService) importPlatforms(entries []ExportPlatformEntry, strategy string, result *ImportResult) {
	// Build existing name→id lookup.
	existing, err := s.Engine.ListPlatforms()
	if err != nil {
		result.Errors = append(result.Errors, "failed to list existing platforms: "+err.Error())
		return
	}
	nameToID := make(map[string]string, len(existing))
	for _, p := range existing {
		nameToID[p.Name] = p.ID
	}

	// Detect duplicates inside the import payload itself.
	seen := make(map[string]bool, len(entries))

	for i, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("platforms[%d]: name is empty, skipped", i))
			continue
		}
		if seen[name] {
			result.Errors = append(result.Errors, fmt.Sprintf("platforms[%d]: duplicate name %q in import payload, skipped", i, name))
			continue
		}
		seen[name] = true

		existingID, exists := nameToID[name]
		if exists && strategy == "skip" {
			result.PlatformsSkipped++
			continue
		}

		if exists && strategy == "overwrite" {
			// Overwrite: build a patch JSON and call UpdatePlatform.
			patch := buildPlatformPatch(entry)
			patchJSON, _ := json.Marshal(patch)
			if _, err := s.UpdatePlatform(existingID, patchJSON); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("platform %q: overwrite failed: %v", name, err))
				continue
			}
			result.PlatformsOverwritten++
			continue
		}

		// Create new platform.
		req := buildCreatePlatformRequest(entry)
		if _, err := s.CreatePlatform(req); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("platform %q: create failed: %v", name, err))
			continue
		}
		result.PlatformsCreated++
	}
}

func (s *ControlPlaneService) importSubscriptions(entries []ExportSubscriptionEntry, strategy string, result *ImportResult) {
	// Build existing name→id and url→id lookup tables.
	existingSubs, err := s.ListSubscriptions(nil)
	if err != nil {
		result.Errors = append(result.Errors, "failed to list existing subscriptions: "+err.Error())
		return
	}
	nameToID := make(map[string]string, len(existingSubs))
	urlToID := make(map[string]string, len(existingSubs))
	for _, sub := range existingSubs {
		nameToID[sub.Name] = sub.ID
		if sub.URL != "" {
			urlToID[sub.URL] = sub.ID
		}
	}

	// Detect duplicates inside the import payload itself.
	seenName := make(map[string]bool, len(entries))
	seenURL := make(map[string]bool, len(entries))

	for i, entry := range entries {
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			result.Errors = append(result.Errors, fmt.Sprintf("subscriptions[%d]: name is empty, skipped", i))
			continue
		}

		// Internal dedup by name.
		if seenName[name] {
			result.Errors = append(result.Errors, fmt.Sprintf("subscriptions[%d]: duplicate name %q in import payload, skipped", i, name))
			continue
		}
		seenName[name] = true

		// Internal dedup by URL for remote subs.
		url := strings.TrimSpace(entry.URL)
		if entry.SourceType == "remote" && url != "" {
			if seenURL[url] {
				result.Errors = append(result.Errors, fmt.Sprintf("subscriptions[%d]: duplicate url %q in import payload, skipped", i, url))
				continue
			}
			seenURL[url] = true
		}

		// Match against existing: first by name, then by URL.
		existingID := ""
		if id, ok := nameToID[name]; ok {
			existingID = id
		} else if entry.SourceType == "remote" && url != "" {
			if id, ok := urlToID[url]; ok {
				existingID = id
			}
		}

		if existingID != "" && strategy == "skip" {
			result.SubscriptionsSkipped++
			continue
		}

		if existingID != "" && strategy == "overwrite" {
			patch := buildSubscriptionPatch(entry)
			patchJSON, _ := json.Marshal(patch)
			if _, err := s.UpdateSubscription(existingID, patchJSON); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("subscription %q: overwrite failed: %v", name, err))
				continue
			}
			result.SubscriptionsOverwritten++
			continue
		}

		// Create new subscription.
		req := buildCreateSubscriptionRequest(entry)
		if _, err := s.CreateSubscription(req); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("subscription %q: create failed: %v", name, err))
			continue
		}
		result.SubscriptionsCreated++
	}
}

// ------------------------------------------------------------------
// helpers: build request structs from export entries
// ------------------------------------------------------------------

func buildCreatePlatformRequest(e ExportPlatformEntry) CreatePlatformRequest {
	name := strings.TrimSpace(e.Name)
	return CreatePlatformRequest{
		Name:                             &name,
		StickyTTL:                        strPtr(e.StickyTTL),
		RegexFilters:                     e.RegexFilters,
		RegionFilters:                    e.RegionFilters,
		AllocationPolicy:                 strPtr(e.AllocationPolicy),
		ReverseProxyMissAction:           strPtr(e.ReverseProxyMissAction),
		ReverseProxyEmptyAccountBehavior: strPtr(e.ReverseProxyEmptyAccountBehavior),
		ReverseProxyFixedAccountHeader:   strPtr(e.ReverseProxyFixedAccountHeader),
	}
}

func buildPlatformPatch(e ExportPlatformEntry) map[string]any {
	patch := map[string]any{
		"sticky_ttl":                          e.StickyTTL,
		"regex_filters":                       e.RegexFilters,
		"region_filters":                      e.RegionFilters,
		"allocation_policy":                   e.AllocationPolicy,
		"reverse_proxy_miss_action":           e.ReverseProxyMissAction,
		"reverse_proxy_empty_account_behavior": e.ReverseProxyEmptyAccountBehavior,
		"reverse_proxy_fixed_account_header":   e.ReverseProxyFixedAccountHeader,
	}
	return patch
}

func buildCreateSubscriptionRequest(e ExportSubscriptionEntry) CreateSubscriptionRequest {
	name := strings.TrimSpace(e.Name)
	sourceType := e.SourceType
	url := strings.TrimSpace(e.URL)
	content := e.Content
	enabled := e.Enabled
	ephemeral := e.Ephemeral
	return CreateSubscriptionRequest{
		Name:                    &name,
		SourceType:              &sourceType,
		URL:                     &url,
		Content:                 &content,
		UpdateInterval:          strPtr(e.UpdateInterval),
		Enabled:                 &enabled,
		Ephemeral:               &ephemeral,
		EphemeralNodeEvictDelay: strPtr(e.EphemeralNodeEvictDelay),
	}
}

func buildSubscriptionPatch(e ExportSubscriptionEntry) map[string]any {
	patch := map[string]any{
		"name":                       strings.TrimSpace(e.Name),
		"update_interval":            e.UpdateInterval,
		"enabled":                    e.Enabled,
		"ephemeral":                  e.Ephemeral,
		"ephemeral_node_evict_delay": e.EphemeralNodeEvictDelay,
	}
	if e.SourceType == "remote" {
		patch["url"] = strings.TrimSpace(e.URL)
	}
	if e.SourceType == "local" {
		patch["content"] = e.Content
	}
	return patch
}

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
