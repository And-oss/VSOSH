package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"example.com/k8s-audit/internal/audit"
	"example.com/k8s-audit/internal/k8s"
	"example.com/k8s-audit/internal/model"
	"example.com/k8s-audit/internal/report"
)

func main() {
	var (
		outPath      string
		format       string
		nsFilter     string
		thresholdStr string
		probeIMDS    bool
		includeKube  bool
	)

	flag.StringVar(&outPath, "out", "", "output JSON file path (default: stdout)")
	flag.StringVar(&format, "format", "text", "output format: text|json")
	flag.StringVar(&nsFilter, "namespace", "", "only scan this namespace (default: all)")
	flag.StringVar(&thresholdStr, "fail-on", "HIGH", "exit with code 2 if findings >= this severity (LOW|MEDIUM|HIGH|CRITICAL)")
	flag.BoolVar(&probeIMDS, "probe-imds", false, "active probe to 169.254.169.254 from this Pod")
	flag.BoolVar(&includeKube, "include-kube-system", false, "include kube-system namespace")
	flag.Parse()

	threshold, err := model.ParseSeverity(thresholdStr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	client, err := k8s.NewInClusterClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to init in-cluster client:", err)
		fmt.Fprintln(os.Stderr, "Tip: run inside Kubernetes Pod with a ServiceAccount token mounted.")
		os.Exit(2)
	}

	notes := map[string]string{}

	namespaces, err := client.ListNamespaces()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to list namespaces:", err)
		os.Exit(2)
	}
	if nsFilter != "" {
		filtered := []k8s.Namespace{}
		for _, ns := range namespaces {
			if ns.Metadata.Name == nsFilter {
				filtered = append(filtered, ns)
			}
		}
		namespaces = filtered
	}
	if !includeKube {
		filtered := []k8s.Namespace{}
		for _, ns := range namespaces {
			if ns.Metadata.Name == "kube-system" {
				continue
			}
			filtered = append(filtered, ns)
		}
		namespaces = filtered
	}

	sas, err := client.ListServiceAccountsAll()
	if err != nil {
		notes["serviceaccounts"] = "cannot list serviceaccounts: " + err.Error()
		sas = nil
	}
	saIndex := map[string]k8s.ServiceAccount{}
	for _, sa := range sas {
		saIndex[sa.Metadata.Namespace+"/"+sa.Metadata.Name] = sa
	}

	pods, err := client.ListPodsAll()
	if err != nil {
		notes["pods"] = "cannot list pods: " + err.Error()
		pods = nil
	}
	if len(namespaces) > 0 {
		allowed := map[string]struct{}{}
		for _, ns := range namespaces {
			allowed[ns.Metadata.Name] = struct{}{}
		}
		filtered := []k8s.Pod{}
		for _, p := range pods {
			if _, ok := allowed[p.Metadata.Namespace]; ok {
				filtered = append(filtered, p)
			}
		}
		pods = filtered
	}

	roles, err := client.ListRolesAll()
	if err != nil {
		notes["roles"] = "cannot list roles: " + err.Error()
		roles = nil
	}
	rbs, err := client.ListRoleBindingsAll()
	if err != nil {
		notes["rolebindings"] = "cannot list rolebindings: " + err.Error()
		rbs = nil
	}
	clusterRoles, err := client.ListClusterRoles()
	if err != nil {
		notes["clusterroles"] = "cannot list clusterroles: " + err.Error()
		clusterRoles = nil
	}
	crbs, err := client.ListClusterRoleBindings()
	if err != nil {
		notes["clusterrolebindings"] = "cannot list clusterrolebindings: " + err.Error()
		crbs = nil
	}

	nps, err := client.ListNetworkPoliciesAll()
	if err != nil {
		notes["networkpolicies"] = "cannot list networkpolicies: " + err.Error()
		nps = nil
	}
	svcs, err := client.ListServicesAll()
	if err != nil {
		notes["services"] = "cannot list services: " + err.Error()
		svcs = nil
	}
	ing, err := client.ListIngressesAll()
	if err != nil {
		notes["ingresses"] = "cannot list ingresses: " + err.Error()
		ing = nil
	}

	if _, err := client.ListNodes(); err != nil {
		notes["nodes"] = "cannot list nodes (ok for read-only mode): " + err.Error()
	}

	findings := []model.Finding{}
	findings = append(findings, audit.DetectNamespacePSS(namespaces)...)
	findings = append(findings, audit.DetectPodMisconfigs(pods, saIndex)...)
	if len(sas) > 0 || len(rbs) > 0 || len(crbs) > 0 {
		e := audit.BuildEffectiveRBAC(sas, roles, clusterRoles, rbs, crbs)
		findings = append(findings, audit.DetectRBAC(e)...)
		findings = append(findings, audit.DetectClusterRolesDirect(clusterRoles)...)
	}
	findings = append(findings, audit.DetectNetwork(namespaces, nps, svcs, ing)...)
	findings = append(findings, audit.DetectIMDSProbe(probeIMDS)...)

	rep := model.Report{
		Cluster: model.ClusterMeta{
			ServerVersion: client.ServerVersion(),
			APIServer:     client.BaseURL(),
		},
		GeneratedAt: time.Now().UTC(),
		Summary:     report.Summarize(findings),
		Findings:    findings,
		Notes:       notes,
	}

	format = strings.ToLower(strings.TrimSpace(format))
	switch format {
	case "text":
		report.PrintTextReport(rep)
		if outPath != "" {
			_ = report.WriteJSON(outPath, rep)
		}
	case "json":
		if err := report.WriteJSON(outPath, rep); err != nil {
			fmt.Fprintln(os.Stderr, "write json:", err)
			os.Exit(2)
		}
	default:
		fmt.Fprintln(os.Stderr, "unknown format:", format)
		os.Exit(2)
	}

	fail := false
	for _, f := range findings {
		if model.SeverityRank(f.Severity) >= model.SeverityRank(threshold) {
			fail = true
			break
		}
	}
	if fail {
		os.Exit(2)
	}
}
