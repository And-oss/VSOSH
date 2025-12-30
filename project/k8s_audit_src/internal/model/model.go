package model

import (
	"fmt"
	"strings"
	"time"
)

// Finding model

type Severity string

const (
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

func SeverityRank(s Severity) int {
	switch s {
	case SeverityLow:
		return 1
	case SeverityMedium:
		return 2
	case SeverityHigh:
		return 3
	case SeverityCritical:
		return 4
	default:
		return 0
	}
}

// ResourceRef describes the k8s object related to a finding.
type ResourceRef struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace,omitempty"`
	Name      string `json:"name"`
}

// Finding is a single check result.
type Finding struct {
	CheckID        string      `json:"checkId"`
	Severity       Severity    `json:"severity"`
	Resource       ResourceRef `json:"resource"`
	Title          string      `json:"title"`
	Evidence       string      `json:"evidence"`
	Risk           string      `json:"risk,omitempty"`
	Recommendation string      `json:"recommendation"`
}

// Report is a machine-readable output.
type Report struct {
	Cluster     ClusterMeta       `json:"cluster"`
	GeneratedAt time.Time         `json:"generatedAt"`
	Summary     map[Severity]int  `json:"summary"`
	Findings    []Finding         `json:"findings"`
	Notes       map[string]string `json:"notes,omitempty"`
}

type ClusterMeta struct {
	ServerVersion string `json:"kubernetesVersion,omitempty"`
	APIServer     string `json:"apiServer"`
}

func ParseSeverity(s string) (Severity, error) {
	s = strings.TrimSpace(strings.ToUpper(s))
	switch s {
	case "LOW":
		return SeverityLow, nil
	case "MEDIUM":
		return SeverityMedium, nil
	case "HIGH":
		return SeverityHigh, nil
	case "CRITICAL":
		return SeverityCritical, nil
	default:
		return "", fmt.Errorf("unknown severity %q", s)
	}
}
