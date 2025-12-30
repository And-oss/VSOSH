package report

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"example.com/k8s-audit/internal/model"
)

func Summarize(findings []model.Finding) map[model.Severity]int {
	m := map[model.Severity]int{
		model.SeverityCritical: 0,
		model.SeverityHigh:     0,
		model.SeverityMedium:   0,
		model.SeverityLow:      0,
	}
	for _, f := range findings {
		m[f.Severity]++
	}
	return m
}

func PrintTextReport(r model.Report) {
	fmt.Printf("k8s-audit (in-cluster)\n")
	fmt.Printf("API Server: %s\n", r.Cluster.APIServer)
	if r.Cluster.ServerVersion != "" {
		fmt.Printf("Kubernetes: %s\n", r.Cluster.ServerVersion)
	}
	fmt.Printf("Generated: %s\n\n", r.GeneratedAt.Format(time.RFC3339))
	fmt.Printf("Summary: CRITICAL=%d HIGH=%d MEDIUM=%d LOW=%d\n\n",
		r.Summary[model.SeverityCritical], r.Summary[model.SeverityHigh], r.Summary[model.SeverityMedium], r.Summary[model.SeverityLow])

	sort.Slice(r.Findings, func(i, j int) bool {
		a := model.SeverityRank(r.Findings[i].Severity)
		b := model.SeverityRank(r.Findings[j].Severity)
		if a != b {
			return a > b
		}
		if r.Findings[i].CheckID != r.Findings[j].CheckID {
			return r.Findings[i].CheckID < r.Findings[j].CheckID
		}
		ai := r.Findings[i].Resource.Namespace + "/" + r.Findings[i].Resource.Name
		aj := r.Findings[j].Resource.Namespace + "/" + r.Findings[j].Resource.Name
		return ai < aj
	})

	for _, f := range r.Findings {
		loc := f.Resource.Kind + "/" + f.Resource.Name
		if f.Resource.Namespace != "" {
			loc = f.Resource.Kind + "/" + f.Resource.Namespace + "/" + f.Resource.Name
		}
		fmt.Printf("[%s] %s %s\n", f.Severity, f.CheckID, f.Title)
		fmt.Printf("  Resource: %s\n", loc)
		fmt.Printf("  Evidence: %s\n", f.Evidence)
		if f.Recommendation != "" {
			fmt.Printf("  Fix: %s\n", f.Recommendation)
		}
		fmt.Println()
	}

	if len(r.Notes) > 0 {
		fmt.Println("Notes:")
		keys := make([]string, 0, len(r.Notes))
		for k := range r.Notes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Printf("- %s: %s\n", k, r.Notes[k])
		}
	}
}

func WriteJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	if path == "" {
		_, err := os.Stdout.Write(b)
		if err == nil {
			fmt.Println()
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}
