package audit

import (
	"fmt"
	"net/http"
	"time"

	"example.com/k8s-audit/internal/model"
)

func DetectIMDSProbe(enabled bool) []model.Finding {
	if !enabled {
		return nil
	}
	client := &http.Client{Timeout: 2 * time.Second}
	url := "http://169.254.169.254/"
	req, _ := http.NewRequest("GET", url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return []model.Finding{{
			CheckID:        "K8S-NET-IMDS-001",
			Severity:       model.SeverityLow,
			Resource:       model.ResourceRef{Kind: "Cluster", Name: "(probe)"},
			Title:          "Проверка доступа к IMDS (169.254.169.254)",
			Evidence:       fmt.Sprintf("HTTP GET %s: недоступно (%v)", url, err),
			Risk:           "Если IMDS недоступен — ниже риск утечки cloud-учетных данных",
			Recommendation: "Если кластер в облаке — все равно рекомендуется блокировать egress к IMDS",
		}}
	}
	defer resp.Body.Close()
	sev := model.SeverityHigh
	if resp.StatusCode >= 400 {
		sev = model.SeverityMedium
	}
	return []model.Finding{{
		CheckID:        "K8S-NET-IMDS-001",
		Severity:       sev,
		Resource:       model.ResourceRef{Kind: "Cluster", Name: "(probe)"},
		Title:          "IMDS (169.254.169.254) доступен из Pod'а",
		Evidence:       fmt.Sprintf("HTTP GET %s: status=%d", url, resp.StatusCode),
		Risk:           "В облачных средах IMDS может выдавать временные учетные данные",
		Recommendation: "Блокировать egress к 169.254.169.254/32 и включить IMDSv2/metadata options (если применимо)",
	}}
}
