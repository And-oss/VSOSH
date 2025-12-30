package audit

import (
	"fmt"
	"strings"

	"example.com/k8s-audit/internal/k8s"
	"example.com/k8s-audit/internal/model"
)

func DetectNetwork(namespaces []k8s.Namespace, nps []k8s.NetworkPolicy, svcs []k8s.Service, ing []k8s.Ingress) []model.Finding {
	var out []model.Finding
	byNS := map[string][]k8s.NetworkPolicy{}
	for _, np := range nps {
		byNS[np.Metadata.Namespace] = append(byNS[np.Metadata.Namespace], np)
	}

	for _, ns := range namespaces {
		n := ns.Metadata.Name
		pols := byNS[n]
		if len(pols) == 0 {
			out = append(out, model.Finding{
				CheckID:        "K8S-NET-001",
				Severity:       model.SeverityHigh,
				Resource:       model.ResourceRef{Kind: "Namespace", Name: n},
				Title:          "В namespace нет NetworkPolicy (по умолчанию allow-all)",
				Evidence:       "networkpolicies=0",
				Risk:           "Отсутствие сегментации упрощает боковое перемещение",
				Recommendation: "Добавить default-deny ingress/egress и разрешать только нужный трафик",
			})
			continue
		}

		denyIngress := false
		denyEgress := false
		for _, np := range pols {
			selectsAll := len(np.Spec.PodSelector.MatchLabels) == 0
			if !selectsAll {
				continue
			}
			pt := uniqStrings(np.Spec.PolicyTypes)
			if len(pt) == 0 {
				if np.Spec.Ingress != nil {
					pt = append(pt, "Ingress")
				}
				if np.Spec.Egress != nil {
					pt = append(pt, "Egress")
				}
				pt = uniqStrings(pt)
			}
			if containsAny(pt, "Ingress") {
				if np.Spec.Ingress != nil && len(np.Spec.Ingress) == 0 {
					denyIngress = true
				}
			}
			if containsAny(pt, "Egress") {
				if np.Spec.Egress != nil && len(np.Spec.Egress) == 0 {
					denyEgress = true
				}
			}
		}
		if !denyIngress {
			out = append(out, model.Finding{
				CheckID:        "K8S-NET-002",
				Severity:       model.SeverityMedium,
				Resource:       model.ResourceRef{Kind: "Namespace", Name: n},
				Title:          "Нет default-deny Ingress для всех Pod'ов",
				Evidence:       "не найден NetworkPolicy с podSelector:{} и ingress:[]",
				Risk:           "Входящий трафик к Pod'ам может быть открыт шире, чем требуется",
				Recommendation: "Добавить default-deny ingress policy (podSelector: {})",
			})
		}
		if !denyEgress {
			out = append(out, model.Finding{
				CheckID:        "K8S-NET-003",
				Severity:       model.SeverityMedium,
				Resource:       model.ResourceRef{Kind: "Namespace", Name: n},
				Title:          "Нет default-deny Egress для всех Pod'ов",
				Evidence:       "не найден NetworkPolicy с podSelector:{} и egress:[]",
				Risk:           "Исходящий трафик может позволить утечки и доступ к внешним сервисам",
				Recommendation: "Добавить default-deny egress и разрешить только нужные направления",
			})
		}
	}

	for _, s := range svcs {
		if strings.EqualFold(s.Spec.Type, "NodePort") {
			ports := []string{}
			for _, p := range s.Spec.Ports {
				ports = append(ports, fmt.Sprintf("%d->%d/%s", p.Port, p.NodePort, strings.ToUpper(p.Protocol)))
			}
			out = append(out, model.Finding{
				CheckID:        "K8S-NET-004",
				Severity:       model.SeverityHigh,
				Resource:       model.ResourceRef{Kind: "Service", Namespace: s.Metadata.Namespace, Name: s.Metadata.Name},
				Title:          "Service типа NodePort",
				Evidence:       fmt.Sprintf("type=NodePort ports=%v", ports),
				Risk:           "NodePort расширяет поверхность атаки (порт на узлах)",
				Recommendation: "Избегать NodePort, использовать Ingress/LoadBalancer с явным контролем доступа",
			})
		}
		if strings.EqualFold(s.Spec.Type, "LoadBalancer") {
			out = append(out, model.Finding{
				CheckID:        "K8S-NET-006",
				Severity:       model.SeverityMedium,
				Resource:       model.ResourceRef{Kind: "Service", Namespace: s.Metadata.Namespace, Name: s.Metadata.Name},
				Title:          "Service типа LoadBalancer",
				Evidence:       "type=LoadBalancer",
				Risk:           "Возможна внешняя экспозиция сервиса",
				Recommendation: "Проверить необходимость внешнего доступа и ограничить источники, настроить TLS",
			})
		}
	}

	for _, ig := range ing {
		out = append(out, model.Finding{
			CheckID:        "K8S-NET-005",
			Severity:       model.SeverityMedium,
			Resource:       model.ResourceRef{Kind: "Ingress", Namespace: ig.Metadata.Namespace, Name: ig.Metadata.Name},
			Title:          "Ingress объект присутствует",
			Evidence:       "networking.k8s.io/v1 Ingress",
			Risk:           "Ingress открывает входящий трафик",
			Recommendation: "Проверить TLS, auth, whitelist и корректность правил",
		})
	}

	return out
}
