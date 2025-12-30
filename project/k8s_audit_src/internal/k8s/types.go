package k8s

// Minimal Kubernetes types (only fields used by audit).

type ObjectMeta struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type ListMeta struct {
	Continue string `json:"continue,omitempty"`
}

// Namespace

type Namespace struct {
	Metadata ObjectMeta `json:"metadata"`
}

type NamespaceList struct {
	Items    []Namespace `json:"items"`
	Metadata ListMeta    `json:"metadata"`
}

// ServiceAccount

type ServiceAccount struct {
	Metadata                     ObjectMeta `json:"metadata"`
	AutomountServiceAccountToken *bool      `json:"automountServiceAccountToken,omitempty"`
}

type ServiceAccountList struct {
	Items    []ServiceAccount `json:"items"`
	Metadata ListMeta         `json:"metadata"`
}

// Pod

type PodList struct {
	Items    []Pod    `json:"items"`
	Metadata ListMeta `json:"metadata"`
}

type Pod struct {
	Metadata ObjectMeta `json:"metadata"`
	Spec     PodSpec    `json:"spec"`
}

type PodSpec struct {
	ServiceAccountName           string              `json:"serviceAccountName,omitempty"`
	AutomountServiceAccountToken *bool               `json:"automountServiceAccountToken,omitempty"`
	HostNetwork                  bool                `json:"hostNetwork,omitempty"`
	HostPID                      bool                `json:"hostPID,omitempty"`
	HostIPC                      bool                `json:"hostIPC,omitempty"`
	SecurityContext              *PodSecurityContext `json:"securityContext,omitempty"`
	Containers                   []Container         `json:"containers"`
	InitContainers               []Container         `json:"initContainers,omitempty"`
	Volumes                      []Volume            `json:"volumes,omitempty"`
}

type PodSecurityContext struct {
	RunAsUser      *int64          `json:"runAsUser,omitempty"`
	RunAsNonRoot   *bool           `json:"runAsNonRoot,omitempty"`
	SeccompProfile *SeccompProfile `json:"seccompProfile,omitempty"`
}

type SeccompProfile struct {
	Type string `json:"type"`
}

type Container struct {
	Name            string           `json:"name"`
	SecurityContext *SecurityContext `json:"securityContext,omitempty"`
	Env             []EnvVar         `json:"env,omitempty"`
	EnvFrom         []EnvFromSource  `json:"envFrom,omitempty"`
	VolumeMounts    []VolumeMount    `json:"volumeMounts,omitempty"`
}

type EnvVar struct {
	Name      string        `json:"name"`
	Value     string        `json:"value,omitempty"`
	ValueFrom *EnvVarSource `json:"valueFrom,omitempty"`
}

type EnvVarSource struct {
	SecretKeyRef *SecretKeySelector `json:"secretKeyRef,omitempty"`
}

type SecretKeySelector struct {
	Name string `json:"name"`
	Key  string `json:"key"`
}

type EnvFromSource struct {
	SecretRef *SecretEnvSource `json:"secretRef,omitempty"`
}

type SecretEnvSource struct {
	Name string `json:"name"`
}

type VolumeMount struct {
	Name      string `json:"name"`
	MountPath string `json:"mountPath"`
	ReadOnly  bool   `json:"readOnly,omitempty"`
}

type SecurityContext struct {
	Privileged               *bool           `json:"privileged,omitempty"`
	AllowPrivilegeEscalation *bool           `json:"allowPrivilegeEscalation,omitempty"`
	RunAsUser                *int64          `json:"runAsUser,omitempty"`
	RunAsNonRoot             *bool           `json:"runAsNonRoot,omitempty"`
	ReadOnlyRootFilesystem   *bool           `json:"readOnlyRootFilesystem,omitempty"`
	Capabilities             *Capabilities   `json:"capabilities,omitempty"`
	SeccompProfile           *SeccompProfile `json:"seccompProfile,omitempty"`
}

type Capabilities struct {
	Add  []string `json:"add,omitempty"`
	Drop []string `json:"drop,omitempty"`
}

type Volume struct {
	Name     string                `json:"name"`
	HostPath *HostPathVolumeSource `json:"hostPath,omitempty"`
	Secret   *SecretVolumeSource   `json:"secret,omitempty"`
}

type HostPathVolumeSource struct {
	Path string `json:"path"`
	Type string `json:"type,omitempty"`
}

type SecretVolumeSource struct {
	SecretName string `json:"secretName"`
}

// RBAC

type PolicyRule struct {
	APIGroups []string `json:"apiGroups,omitempty"`
	Resources []string `json:"resources,omitempty"`
	Verbs     []string `json:"verbs,omitempty"`
}

type Role struct {
	Metadata ObjectMeta   `json:"metadata"`
	Rules    []PolicyRule `json:"rules"`
}

type RoleList struct {
	Items    []Role   `json:"items"`
	Metadata ListMeta `json:"metadata"`
}

type ClusterRole struct {
	Metadata ObjectMeta   `json:"metadata"`
	Rules    []PolicyRule `json:"rules"`
}

type ClusterRoleList struct {
	Items    []ClusterRole `json:"items"`
	Metadata ListMeta      `json:"metadata"`
}

type Subject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

type RoleRef struct {
	Kind string `json:"kind"`
	Name string `json:"name"`
}

type RoleBinding struct {
	Metadata ObjectMeta `json:"metadata"`
	Subjects []Subject  `json:"subjects,omitempty"`
	RoleRef  RoleRef    `json:"roleRef"`
}

type RoleBindingList struct {
	Items    []RoleBinding `json:"items"`
	Metadata ListMeta      `json:"metadata"`
}

type ClusterRoleBinding struct {
	Metadata ObjectMeta `json:"metadata"`
	Subjects []Subject  `json:"subjects,omitempty"`
	RoleRef  RoleRef    `json:"roleRef"`
}

type ClusterRoleBindingList struct {
	Items    []ClusterRoleBinding `json:"items"`
	Metadata ListMeta             `json:"metadata"`
}

// NetworkPolicy

type LabelSelector struct {
	MatchLabels map[string]string `json:"matchLabels,omitempty"`
}

type NetworkPolicySpec struct {
	PodSelector LabelSelector `json:"podSelector"`
	PolicyTypes []string      `json:"policyTypes,omitempty"`
	Ingress     []any         `json:"ingress,omitempty"`
	Egress      []any         `json:"egress,omitempty"`
}

type NetworkPolicy struct {
	Metadata ObjectMeta        `json:"metadata"`
	Spec     NetworkPolicySpec `json:"spec"`
}

type NetworkPolicyList struct {
	Items    []NetworkPolicy `json:"items"`
	Metadata ListMeta        `json:"metadata"`
}

// Service

type ServicePort struct {
	Port     int32  `json:"port"`
	NodePort int32  `json:"nodePort,omitempty"`
	Protocol string `json:"protocol"`
}

type ServiceSpec struct {
	Type  string        `json:"type,omitempty"`
	Ports []ServicePort `json:"ports,omitempty"`
}

type Service struct {
	Metadata ObjectMeta  `json:"metadata"`
	Spec     ServiceSpec `json:"spec"`
}

type ServiceList struct {
	Items    []Service `json:"items"`
	Metadata ListMeta  `json:"metadata"`
}

// Ingress

type Ingress struct {
	Metadata ObjectMeta `json:"metadata"`
}

type IngressList struct {
	Items    []Ingress `json:"items"`
	Metadata ListMeta  `json:"metadata"`
}

// Node

type Node struct {
	Metadata ObjectMeta `json:"metadata"`
}

type NodeList struct {
	Items    []Node   `json:"items"`
	Metadata ListMeta `json:"metadata"`
}
