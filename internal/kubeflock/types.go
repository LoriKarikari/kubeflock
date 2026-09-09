package kubeflock

import "time"

const Version = "0.1.0"

const (
	managedByLabel = "app.kubernetes.io/managed-by"
	managedByValue = "kubeflock"
)

type KubeTarget struct {
	Context   string `yaml:"context" json:"context"`
	Namespace string `yaml:"namespace" json:"namespace"`
}

type SandboxIdentity struct {
	Context   string `json:"context"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	UID       string `json:"uid"`
}

type SSHState struct {
	Alias          string `json:"alias"`
	IdentityFile   string `json:"identityFile"`
	KnownHostsFile string `json:"knownHostsFile"`
	EntryFile      string `json:"entryFile"`
	ProxyFile      string `json:"proxyFile"`
	ConfigFile     string `json:"configFile"`
	HostKey        string `json:"hostKey"`
}

type HerdrState struct {
	Label   string `json:"label"`
	Session string `json:"session"`
}

type Connection struct {
	Version    int             `json:"version"`
	Phase      string          `json:"phase"`
	Sandbox    SandboxIdentity `json:"sandbox"`
	SSH        SSHState        `json:"ssh"`
	Herdr      HerdrState      `json:"herdr"`
	Kubeconfig *string         `json:"kubeconfig"`
	Kubectl    string          `json:"kubectl"`
	ProfileID  string          `json:"profileId,omitempty"`
}

type PersistentHome struct {
	Name         string `json:"name"`
	UID          string `json:"uid"`
	Capacity     string `json:"capacity"`
	StorageClass string `json:"storageClass"`
}

type ManagedSandbox struct {
	Version      int              `json:"version"`
	Phase        string           `json:"phase"`
	Claim        SandboxIdentity  `json:"claim"`
	Template     string           `json:"template"`
	WarmPool     string           `json:"warmPool"`
	IdentityFile string           `json:"identityFile"`
	Sandbox      *SandboxIdentity `json:"sandbox,omitempty"`
	Home         *PersistentHome  `json:"home,omitempty"`
}

type CheckResult struct {
	Name        string `json:"name"`
	OK          bool   `json:"ok"`
	Advisory    bool   `json:"advisory,omitempty"`
	Category    string `json:"category,omitempty"`
	Message     string `json:"message"`
	Remediation string `json:"remediation,omitempty"`
}

type CheckReport struct {
	Context   string        `json:"context"`
	Namespace string        `json:"namespace"`
	OK        bool          `json:"ok"`
	Checks    []CheckResult `json:"checks"`
	CheckedAt time.Time     `json:"checkedAt"`
}

type SandboxStatus struct {
	Name       string          `json:"name"`
	Namespace  string          `json:"namespace"`
	State      string          `json:"state"`
	Step       string          `json:"step,omitempty"`
	Message    string          `json:"message,omitempty"`
	ClaimUID   string          `json:"claimUid"`
	SandboxUID string          `json:"sandboxUid,omitempty"`
	Template   string          `json:"template"`
	WarmPool   string          `json:"warmPool"`
	Home       *PersistentHome `json:"home,omitempty"`
}
