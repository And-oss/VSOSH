package audit

import (
	"fmt"
	"strings"

	"example.com/k8s-audit/internal/k8s"
	"example.com/k8s-audit/internal/model"
)

func DetectPodMisconfigs(pods []k8s.Pod, saIndex map[string]k8s.ServiceAccount) []model.Finding {
	var out []model.Finding
	for _, p := range pods {
		ns := p.Metadata.Namespace
		name := p.Metadata.Name

		if p.Spec.HostNetwork || p.Spec.HostPID || p.Spec.HostIPC {
			modes := []string{}
			if p.Spec.HostNetwork {
				modes = append(modes, "hostNetwork")
			}
			if p.Spec.HostPID {
				modes = append(modes, "hostPID")
			}
			if p.Spec.HostIPC {
				modes = append(modes, "hostIPC")
			}
			out = append(out, model.Finding{
				CheckID:        "K8S-POD-003",
				Severity:       model.SeverityHigh,
				Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
				Title:          "Использование host namespace (hostNetwork/hostPID/hostIPC)",
				Evidence:       fmt.Sprintf("spec.%s=true", strings.Join(modes, ", ")),
				Risk:           "Под повышает риск компрометации узла и обхода изоляции контейнеров",
				Recommendation: "Отключить hostNetwork/hostPID/hostIPC, если это не строго необходимо",
			})
		}

		for _, v := range p.Spec.Volumes {
			if v.HostPath != nil {
				out = append(out, model.Finding{
					CheckID:        "K8S-POD-002",
					Severity:       model.SeverityCritical,
					Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
					Title:          "Монтирование hostPath",
					Evidence:       fmt.Sprintf("volume %q: hostPath=%q", v.Name, v.HostPath.Path),
					Risk:           "Доступ к ФС узла может привести к эскалации привилегий и утечке данных",
					Recommendation: "Избегать hostPath. Использовать PVC/CSI или минимально необходимый путь + readOnly",
				})
			}
		}

		automount := true
		if p.Spec.AutomountServiceAccountToken != nil {
			automount = *p.Spec.AutomountServiceAccountToken
		} else {
			saName := p.Spec.ServiceAccountName
			if saName == "" {
				saName = "default"
			}
			if sa, ok := saIndex[ns+"/"+saName]; ok {
				if sa.AutomountServiceAccountToken != nil {
					automount = *sa.AutomountServiceAccountToken
				}
			}
		}
		if automount {
			out = append(out, model.Finding{
				CheckID:        "K8S-POD-008",
				Severity:       model.SeverityMedium,
				Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
				Title:          "Automount ServiceAccount токена включен",
				Evidence:       "automountServiceAccountToken=true (явно или по умолчанию)",
				Risk:           "При компрометации пода токен может быть украден и использован для kube-API",
				Recommendation: "Если доступ к kube-API не нужен — установить automountServiceAccountToken: false",
			})
		}

		containers := append([]k8s.Container{}, p.Spec.InitContainers...)
		containers = append(containers, p.Spec.Containers...)

		var podRunAsUser *int64
		var podRunAsNonRoot *bool
		var podSeccomp *k8s.SeccompProfile
		if p.Spec.SecurityContext != nil {
			podRunAsUser = p.Spec.SecurityContext.RunAsUser
			podRunAsNonRoot = p.Spec.SecurityContext.RunAsNonRoot
			podSeccomp = p.Spec.SecurityContext.SeccompProfile
		}

		for _, ctn := range containers {
			ctx := ctn.SecurityContext

			if ctx != nil && ctx.Privileged != nil && *ctx.Privileged {
				out = append(out, model.Finding{
					CheckID:        "K8S-POD-001",
					Severity:       model.SeverityCritical,
					Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
					Title:          "Privileged контейнер",
					Evidence:       fmt.Sprintf("container %q: securityContext.privileged=true", ctn.Name),
					Risk:           "Privileged контейнер имеет расширенный доступ к ядру и устройствам узла",
					Recommendation: "Убрать privileged. Использовать минимальные capabilities и PSA/Policy",
				})
			}

			effRunAsUser := podRunAsUser
			effRunAsNonRoot := podRunAsNonRoot
			if ctx != nil {
				if ctx.RunAsUser != nil {
					effRunAsUser = ctx.RunAsUser
				}
				if ctx.RunAsNonRoot != nil {
					effRunAsNonRoot = ctx.RunAsNonRoot
				}
			}

			if effRunAsUser != nil && *effRunAsUser == 0 {
				out = append(out, model.Finding{
					CheckID:        "K8S-POD-004",
					Severity:       model.SeverityHigh,
					Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
					Title:          "Контейнер запускается от root",
					Evidence:       fmt.Sprintf("container %q: runAsUser=0", ctn.Name),
					Risk:           "Root в контейнере увеличивает последствия RCE",
					Recommendation: "Установить runAsNonRoot: true и runAsUser на непривилегированный UID",
				})
			} else if effRunAsNonRoot != nil && !*effRunAsNonRoot {
				out = append(out, model.Finding{
					CheckID:        "K8S-POD-004",
					Severity:       model.SeverityHigh,
					Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
					Title:          "runAsNonRoot отключен",
					Evidence:       fmt.Sprintf("container %q: runAsNonRoot=false", ctn.Name),
					Risk:           "Контейнер может стартовать от root",
					Recommendation: "Установить runAsNonRoot: true и runAsUser на непривилегированный UID",
				})
			}

			effSeccomp := podSeccomp
			if ctx != nil && ctx.SeccompProfile != nil {
				effSeccomp = ctx.SeccompProfile
			}
			if effSeccomp == nil || strings.EqualFold(effSeccomp.Type, "Unconfined") {
				ev := "seccompProfile not set"
				if effSeccomp != nil {
					ev = "seccompProfile.type=Unconfined"
				}
				out = append(out, model.Finding{
					CheckID:        "K8S-POD-005",
					Severity:       model.SeverityMedium,
					Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
					Title:          "Seccomp профиль не установлен",
					Evidence:       fmt.Sprintf("container %q: %s", ctn.Name, ev),
					Risk:           "Отсутствие seccomp расширяет набор доступных syscalls",
					Recommendation: "Использовать RuntimeDefault или Localhost профиль",
				})
			}

			if ctx != nil && ctx.AllowPrivilegeEscalation != nil && *ctx.AllowPrivilegeEscalation {
				out = append(out, model.Finding{
					CheckID:        "K8S-POD-006",
					Severity:       model.SeverityHigh,
					Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
					Title:          "AllowPrivilegeEscalation=true",
					Evidence:       fmt.Sprintf("container %q: allowPrivilegeEscalation=true", ctn.Name),
					Risk:           "Позволяет использовать setuid/setgid и повышать привилегии",
					Recommendation: "Установить allowPrivilegeEscalation: false",
				})
			}

			if ctx != nil && ctx.ReadOnlyRootFilesystem != nil && !*ctx.ReadOnlyRootFilesystem {
				out = append(out, model.Finding{
					CheckID:        "K8S-POD-007",
					Severity:       model.SeverityMedium,
					Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
					Title:          "readOnlyRootFilesystem отключен",
					Evidence:       fmt.Sprintf("container %q: readOnlyRootFilesystem=false", ctn.Name),
					Risk:           "Запись в rootfs упрощает закрепление вредоносного кода",
					Recommendation: "Включить readOnlyRootFilesystem: true и монтировать writable тома отдельно",
				})
			}

			if ctx != nil && ctx.Capabilities != nil {
				if len(ctx.Capabilities.Add) > 0 {
					out = append(out, model.Finding{
						CheckID:        "K8S-POD-010",
						Severity:       model.SeverityMedium,
						Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
						Title:          "Добавлены Linux capabilities",
						Evidence:       fmt.Sprintf("container %q: capabilities.add=%v", ctn.Name, ctx.Capabilities.Add),
						Risk:           "Доп. capabilities увеличивают привилегии контейнера",
						Recommendation: "Избегать capabilities.add, использовать allowlist по необходимости",
					})
				}
				if len(ctx.Capabilities.Drop) == 0 {
					out = append(out, model.Finding{
						CheckID:        "K8S-POD-011",
						Severity:       model.SeverityLow,
						Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
						Title:          "Не указан capabilities.drop",
						Evidence:       fmt.Sprintf("container %q: capabilities.drop not set", ctn.Name),
						Risk:           "По умолчанию контейнер сохраняет набор стандартных capabilities",
						Recommendation: "Явно сбросить все capabilities (drop: [\"ALL\"]) и добавить нужные",
					})
				}
			}

			for _, ev := range ctn.Env {
				if ev.ValueFrom != nil && ev.ValueFrom.SecretKeyRef != nil {
					out = append(out, model.Finding{
						CheckID:        "K8S-POD-012",
						Severity:       model.SeverityLow,
						Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
						Title:          "Секреты проброшены в env",
						Evidence:       fmt.Sprintf("container %q: env %q from secret %q", ctn.Name, ev.Name, ev.ValueFrom.SecretKeyRef.Name),
						Risk:           "Секреты в env могут попасть в логи/дампы",
						Recommendation: "Минимизировать секреты в env; избегать вывода env в логи",
					})
				}
			}
			for _, ef := range ctn.EnvFrom {
				if ef.SecretRef != nil {
					out = append(out, model.Finding{
						CheckID:        "K8S-POD-009",
						Severity:       model.SeverityMedium,
						Resource:       model.ResourceRef{Kind: "Pod", Namespace: ns, Name: name},
						Title:          "Секрет импортируется целиком в envFrom",
						Evidence:       fmt.Sprintf("container %q: envFrom secretRef=%q", ctn.Name, ef.SecretRef.Name),
						Risk:           "Увеличивает поверхность утечки секретов через окружение",
						Recommendation: "Импортировать только нужные ключи или использовать volume secret",
					})
				}
			}
		}
	}
	return out
}
