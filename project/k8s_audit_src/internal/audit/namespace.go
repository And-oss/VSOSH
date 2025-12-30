package audit

import (
	"strings"

	"example.com/k8s-audit/internal/k8s"
	"example.com/k8s-audit/internal/model"
)

func DetectNamespacePSS(namespaces []k8s.Namespace) []model.Finding {
	var out []model.Finding
	for _, ns := range namespaces {
		labels := ns.Metadata.Labels
		enforce := ""
		if labels != nil {
			enforce = labels["pod-security.kubernetes.io/enforce"]
		}
		if enforce == "" {
			out = append(out, model.Finding{
				CheckID:        "K8S-PSA-001",
				Severity:       model.SeverityMedium,
				Resource:       model.ResourceRef{Kind: "Namespace", Name: ns.Metadata.Name},
				Title:          "Pod Security Admission (enforce) не настроен",
				Evidence:       "label pod-security.kubernetes.io/enforce отсутствует",
				Risk:           "Кластер может принимать небезопасные Pod'ы без базовых ограничений",
				Recommendation: "Задать pod-security.kubernetes.io/enforce=baseline/restricted",
			})
		} else if strings.EqualFold(enforce, "privileged") {
			out = append(out, model.Finding{
				CheckID:        "K8S-PSA-002",
				Severity:       model.SeverityHigh,
				Resource:       model.ResourceRef{Kind: "Namespace", Name: ns.Metadata.Name},
				Title:          "Pod Security Admission установлен в privileged",
				Evidence:       "pod-security.kubernetes.io/enforce=privileged",
				Risk:           "Позволяет запускать опасные Pod'ы",
				Recommendation: "Понизить до baseline/restricted и оформлять исключения точечно",
			})
		}
	}
	return out
}
