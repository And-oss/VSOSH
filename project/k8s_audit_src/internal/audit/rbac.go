package audit

import (
	"fmt"
	"strings"

	"example.com/k8s-audit/internal/k8s"
	"example.com/k8s-audit/internal/model"
)

// RBAC graph: bind SA -> role rules.

type BoundRole struct {
	RoleKind  string
	RoleNS    string
	RoleName  string
	Binding   string
	BindingNS string
	Rules     []k8s.PolicyRule
}

type EffectiveRBAC struct {
	BySA map[string][]BoundRole
}

func BuildEffectiveRBAC(sas []k8s.ServiceAccount, roles []k8s.Role, cRoles []k8s.ClusterRole, rbs []k8s.RoleBinding, crbs []k8s.ClusterRoleBinding) EffectiveRBAC {
	roleIndex := map[string]k8s.Role{}
	for _, r := range roles {
		roleIndex[r.Metadata.Namespace+"/"+r.Metadata.Name] = r
	}
	cRoleIndex := map[string]k8s.ClusterRole{}
	for _, r := range cRoles {
		cRoleIndex[r.Metadata.Name] = r
	}

	bySA := map[string][]BoundRole{}
	add := func(saNS, saName string, br BoundRole) {
		key := saNS + "/" + saName
		bySA[key] = append(bySA[key], br)
	}

	for _, rb := range rbs {
		bNS := rb.Metadata.Namespace
		for _, sub := range rb.Subjects {
			if sub.Kind != "ServiceAccount" {
				continue
			}
			saNS := sub.Namespace
			if saNS == "" {
				saNS = bNS
			}
			br := BoundRole{
				RoleKind:  rb.RoleRef.Kind,
				RoleName:  rb.RoleRef.Name,
				Binding:   rb.Metadata.Name,
				BindingNS: bNS,
			}
			if rb.RoleRef.Kind == "Role" {
				br.RoleNS = bNS
				if r, ok := roleIndex[bNS+"/"+rb.RoleRef.Name]; ok {
					br.Rules = r.Rules
				}
			} else if rb.RoleRef.Kind == "ClusterRole" {
				if cr, ok := cRoleIndex[rb.RoleRef.Name]; ok {
					br.Rules = cr.Rules
				}
			}
			add(saNS, sub.Name, br)
		}
	}

	for _, crb := range crbs {
		for _, sub := range crb.Subjects {
			if sub.Kind != "ServiceAccount" {
				continue
			}
			if sub.Namespace == "" {
				continue
			}
			br := BoundRole{
				RoleKind:  crb.RoleRef.Kind,
				RoleName:  crb.RoleRef.Name,
				Binding:   crb.Metadata.Name,
				BindingNS: "(cluster)",
			}
			if crb.RoleRef.Kind == "ClusterRole" {
				if cr, ok := cRoleIndex[crb.RoleRef.Name]; ok {
					br.Rules = cr.Rules
				}
			}
			add(sub.Namespace, sub.Name, br)
		}
	}

	for _, sa := range sas {
		key := sa.Metadata.Namespace + "/" + sa.Metadata.Name
		if _, ok := bySA[key]; !ok {
			bySA[key] = nil
		}
	}
	return EffectiveRBAC{BySA: bySA}
}

func DetectRBAC(e EffectiveRBAC) []model.Finding {
	var out []model.Finding
	for saKey, bound := range e.BySA {
		parts := strings.SplitN(saKey, "/", 2)
		saNS, saName := parts[0], parts[1]
		for _, br := range bound {
			if len(br.Rules) == 0 {
				continue
			}
			if br.RoleKind == "ClusterRole" && br.RoleName == "cluster-admin" {
				out = append(out, model.Finding{
					CheckID:        "K8S-RBAC-000",
					Severity:       model.SeverityCritical,
					Resource:       model.ResourceRef{Kind: "ServiceAccount", Namespace: saNS, Name: saName},
					Title:          "ServiceAccount привязан к cluster-admin",
					Evidence:       fmt.Sprintf("binding %q (%s) -> clusterrole %q", br.Binding, br.BindingNS, br.RoleName),
					Risk:           "Компрометация токена SA даёт полный контроль над кластером",
					Recommendation: "Убрать cluster-admin, выдать минимально необходимые права",
				})
			}

			for _, rule := range br.Rules {
				if hasStar(rule.Verbs) || hasStar(rule.Resources) || hasStar(rule.APIGroups) {
					out = append(out, model.Finding{
						CheckID:        "K8S-RBAC-001",
						Severity:       model.SeverityHigh,
						Resource:       model.ResourceRef{Kind: "ServiceAccount", Namespace: saNS, Name: saName},
						Title:          "Избыточные RBAC-права (wildcard)",
						Evidence:       fmt.Sprintf("binding %q -> %s %q: apiGroups=%v resources=%v verbs=%v", br.Binding, strings.ToLower(br.RoleKind), br.RoleName, rule.APIGroups, rule.Resources, rule.Verbs),
						Risk:           "Wildcard правила часто позволяют выполнять опасные операции в kube-API",
						Recommendation: "Заменить '*' на конкретные ресурсы/verbs и ограничить по namespace",
					})
				}

				res := uniqStrings(rule.Resources)
				verbs := uniqStrings(rule.Verbs)

				if containsAny(res, "secrets") && containsAny(verbs, "get", "list", "watch") {
					out = append(out, model.Finding{
						CheckID:        "K8S-RBAC-002",
						Severity:       model.SeverityHigh,
						Resource:       model.ResourceRef{Kind: "ServiceAccount", Namespace: saNS, Name: saName},
						Title:          "RBAC: доступ к secrets",
						Evidence:       fmt.Sprintf("binding %q -> %s %q: resources include secrets, verbs=%v", br.Binding, strings.ToLower(br.RoleKind), br.RoleName, verbs),
						Risk:           "Позволяет читать секреты и расширять компрометацию",
						Recommendation: "Убрать доступ к secrets для прикладных SA",
					})
				}

				if containsAny(res, "pods/exec") && containsAny(verbs, "create", "get") {
					out = append(out, model.Finding{
						CheckID:        "K8S-RBAC-003",
						Severity:       model.SeverityHigh,
						Resource:       model.ResourceRef{Kind: "ServiceAccount", Namespace: saNS, Name: saName},
						Title:          "RBAC: доступ к pods/exec",
						Evidence:       fmt.Sprintf("binding %q -> %s %q: resources include pods/exec, verbs=%v", br.Binding, strings.ToLower(br.RoleKind), br.RoleName, verbs),
						Risk:           "Позволяет выполнять команды в контейнерах",
						Recommendation: "Ограничить pods/exec только операторам/SRE при необходимости",
					})
				}

				if containsAny(res, "nodes") {
					out = append(out, model.Finding{
						CheckID:        "K8S-RBAC-004",
						Severity:       model.SeverityHigh,
						Resource:       model.ResourceRef{Kind: "ServiceAccount", Namespace: saNS, Name: saName},
						Title:          "RBAC: доступ к nodes",
						Evidence:       fmt.Sprintf("binding %q -> %s %q: resources include nodes, verbs=%v", br.Binding, strings.ToLower(br.RoleKind), br.RoleName, verbs),
						Risk:           "Доступ к узлам помогает собирать чувствительную информацию",
						Recommendation: "Убрать доступ к nodes для прикладных сервисов",
					})
				}

				if containsAny(res, "rolebindings", "clusterrolebindings") && containsAny(verbs, "create", "patch", "update") {
					out = append(out, model.Finding{
						CheckID:        "K8S-RBAC-005",
						Severity:       model.SeverityCritical,
						Resource:       model.ResourceRef{Kind: "ServiceAccount", Namespace: saNS, Name: saName},
						Title:          "RBAC: возможность изменять привязки ролей",
						Evidence:       fmt.Sprintf("binding %q -> %s %q: resources include rolebindings/clusterrolebindings, verbs=%v", br.Binding, strings.ToLower(br.RoleKind), br.RoleName, verbs),
						Risk:           "Позволяет расширить собственные права (эскалация в kube-API)",
						Recommendation: "Запретить сервисам изменять rolebindings/clusterrolebindings",
					})
				}
			}
		}
	}
	return out
}

func DetectClusterRolesDirect(clusterRoles []k8s.ClusterRole) []model.Finding {
	var out []model.Finding
	for _, cr := range clusterRoles {
		for _, rule := range cr.Rules {
			if hasStar(rule.Verbs) || hasStar(rule.Resources) || hasStar(rule.APIGroups) {
				out = append(out, model.Finding{
					CheckID:        "K8S-RBAC-101",
					Severity:       model.SeverityMedium,
					Resource:       model.ResourceRef{Kind: "ClusterRole", Name: cr.Metadata.Name},
					Title:          "ClusterRole содержит wildcard правила",
					Evidence:       fmt.Sprintf("apiGroups=%v resources=%v verbs=%v", rule.APIGroups, rule.Resources, rule.Verbs),
					Risk:           "Wildcard roles приводят к избыточным правам при привязке",
					Recommendation: "Ограничить rules до нужных ресурсов и verbs",
				})
			}
		}
	}
	return out
}
