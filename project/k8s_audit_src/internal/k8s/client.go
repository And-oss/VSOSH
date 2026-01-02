package k8s

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)


type Client struct {
	baseURL string
	hc      *http.Client
	token   string
}

func NewInClusterClient() (*Client, error) {
	host := os.Getenv("KUBERNETES_SERVICE_HOST")
	port := os.Getenv("KUBERNETES_SERVICE_PORT")
	if host == "" || port == "" {
		host = "kubernetes.default.svc"
		port = "443"
	}
	base := fmt.Sprintf("https://%s:%s", host, port)

	tokenPath := "/var/run/secrets/kubernetes.io/serviceaccount/token"
	caPath := "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

	tokBytes, err := os.ReadFile(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("read serviceaccount token: %w", err)
	}
	token := strings.TrimSpace(string(tokBytes))

	caBytes, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read serviceaccount CA: %w", err)
	}
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(caBytes); !ok {
		return nil, errors.New("failed to parse CA cert")
	}

	tlsCfg := &tls.Config{RootCAs: roots}
	tr := &http.Transport{TLSClientConfig: tlsCfg}

	return &Client{
		baseURL: base,
		hc:      &http.Client{Transport: tr, Timeout: 30 * time.Second},
		token:   token,
	}, nil
}

func (c *Client) BaseURL() string {
	return c.baseURL
}

func (c *Client) doGET(path string) ([]byte, error) {
	req, err := http.NewRequest("GET", c.baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("GET %s: status %d: %s", path, resp.StatusCode, truncate(string(body), 300))
	}
	return body, nil
}

func (c *Client) ServerVersion() string {
	b, err := c.doGET("/version")
	if err != nil {
		return ""
	}
	var v struct {
		GitVersion string `json:"gitVersion"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		return ""
	}
	return v.GitVersion
}

// API list helpers.

func listAll[T any](c *Client, path string, into func([]byte) (items []T, cont string, err error)) ([]T, error) {
	var all []T
	cont := ""
	for {
		p := path
		if cont != "" {
			sep := "?"
			if strings.Contains(p, "?") {
				sep = "&"
			}
			p = fmt.Sprintf("%s%vcontinue=%s", p, sep, cont)
		}
		b, err := c.doGET(p)
		if err != nil {
			return nil, err
		}
		items, next, err := into(b)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if next == "" {
			break
		}
		cont = next
	}
	return all, nil
}

func (c *Client) ListNamespaces() ([]Namespace, error) {
	return listAll[Namespace](c, "/api/v1/namespaces", func(b []byte) ([]Namespace, string, error) {
		var lst NamespaceList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListServiceAccountsAll() ([]ServiceAccount, error) {
	return listAll[ServiceAccount](c, "/api/v1/serviceaccounts", func(b []byte) ([]ServiceAccount, string, error) {
		var lst ServiceAccountList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListPodsAll() ([]Pod, error) {
	return listAll[Pod](c, "/api/v1/pods", func(b []byte) ([]Pod, string, error) {
		var lst PodList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListRolesAll() ([]Role, error) {
	return listAll[Role](c, "/apis/rbac.authorization.k8s.io/v1/roles", func(b []byte) ([]Role, string, error) {
		var lst RoleList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListRoleBindingsAll() ([]RoleBinding, error) {
	return listAll[RoleBinding](c, "/apis/rbac.authorization.k8s.io/v1/rolebindings", func(b []byte) ([]RoleBinding, string, error) {
		var lst RoleBindingList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListClusterRoles() ([]ClusterRole, error) {
	return listAll[ClusterRole](c, "/apis/rbac.authorization.k8s.io/v1/clusterroles", func(b []byte) ([]ClusterRole, string, error) {
		var lst ClusterRoleList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListClusterRoleBindings() ([]ClusterRoleBinding, error) {
	return listAll[ClusterRoleBinding](c, "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings", func(b []byte) ([]ClusterRoleBinding, string, error) {
		var lst ClusterRoleBindingList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListNetworkPoliciesAll() ([]NetworkPolicy, error) {
	return listAll[NetworkPolicy](c, "/apis/networking.k8s.io/v1/networkpolicies", func(b []byte) ([]NetworkPolicy, string, error) {
		var lst NetworkPolicyList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListServicesAll() ([]Service, error) {
	return listAll[Service](c, "/api/v1/services", func(b []byte) ([]Service, string, error) {
		var lst ServiceList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListIngressesAll() ([]Ingress, error) {
	return listAll[Ingress](c, "/apis/networking.k8s.io/v1/ingresses", func(b []byte) ([]Ingress, string, error) {
		var lst IngressList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func (c *Client) ListNodes() ([]Node, error) {
	return listAll[Node](c, "/api/v1/nodes", func(b []byte) ([]Node, string, error) {
		var lst NodeList
		err := json.Unmarshal(b, &lst)
		return lst.Items, lst.Metadata.Continue, err
	})
}

func truncate(s string, n int) string {
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
