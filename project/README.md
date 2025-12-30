# Vuln Kubernetes Lab (2–3 nodes) — стенд для проверки детектов 


## Быстрый старт

```bash
kind create cluster --config kind-config.yaml
kubectl cluster-info
kubectl get nodes -o wide
```

Apply 
```bash
kubectl apply -f 00-namespaces.yaml
kubectl apply -f 10-rbac.yaml
kubectl apply -f 20-pods-vuln.yaml
kubectl apply -f 30-network.yaml
kubectl apply -f 40-services.yaml
```

Check
```bash
kubectl get ns
kubectl get all -A | head
kubectl -n lab-vuln get pods -o wide
kubectl -n lab-vuln describe pod privileged-hostpath | sed -n '1,120p'
```

Delete
```bash
kind delete cluster --name vuln-lab
```

## Уязвимости
- RBAC: ClusterRole с `*` + ClusterRoleBinding на ServiceAccount (эскалация прав)
- Pods: privileged, hostPath, hostNetwork/hostPID, NET_RAW/NET_ADMIN, seccomp Unconfined, runAsUser=0
- Сеть: namespace без NetworkPolicy (allow-all), NodePort наружу
- Egress/IMDS: namespace с default-deny-egress + явное разрешение egress на 169.254.169.254/32 (как "IMDS")
