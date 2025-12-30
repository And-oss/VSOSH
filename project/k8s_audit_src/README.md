# k8s-audit

Минимальный in-cluster аудит Kubernetes с детекторами базовых misconfig и RBAC.

## Структура проекта

- cmd/k8s-audit/main.go — входная точка, парсинг флагов, сбор данных, запуск детекторов.
- internal/model — модели Findings/Report и Severity.
- internal/k8s — минимальные типы K8s и REST-клиент для in-cluster доступа.
- internal/audit — детекторы (pods, RBAC, network, namespace, IMDS) и утилиты.
- internal/report — текстовый/JSON-отчет и агрегация Summary.

## Запуск

Внутри Pod'а с примонтированным ServiceAccount токеном:

Флаги:
- -format text|json
- -out <path>
- -namespace <name>
- -fail-on LOW|MEDIUM|HIGH|CRITICAL
- -probe-imds
- -include-kube-system


## Docker + kind

Сборка образа:

```
docker build -t k8s-audit:local .
```

Загрузка в kind-кластер:

```
kind load docker-image k8s-audit:local --name vuln-lab
```

---
---

How to use it? 


1. write an audit for vulnerable 
2. push audit into cluster
```
kubectl apply -f rbac-audit.yaml

```
3. push job audit(worker) to cluster 

```
kubectl apply -f job-audit.yaml
kubectl -n audit logs job/k8s-audit > report.json
```

