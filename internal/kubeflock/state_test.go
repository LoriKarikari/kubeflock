package kubeflock

import "testing"

func TestStateValidationRejectsIncompleteRecords(t *testing.T) {
	connection := Connection{
		Version:   1,
		Phase:     "connected",
		ProfileID: "profile",
		Sandbox:   SandboxIdentity{Context: "homelab", Namespace: "developer", Name: "sandbox", UID: "sandbox-uid"},
		SSH: SSHState{
			Alias:          "alias",
			IdentityFile:   "identity",
			KnownHostsFile: "known-hosts",
			EntryFile:      "entry",
			ProxyFile:      "proxy",
			ConfigFile:     "config",
			HostKey:        "host-key",
		},
	}
	if err := validateConnection(connection); err != nil {
		t.Fatalf("valid connection rejected: %v", err)
	}
	connection.ProfileID = ""
	if err := validateConnection(connection); err == nil {
		t.Fatal("connected connection without profile ID was accepted")
	}
	connection = Connection{
		Version: 1,
		Phase:   "prepared",
		Sandbox: SandboxIdentity{Context: "homelab", Namespace: "developer", Name: "sandbox"},
		SSH: SSHState{
			Alias:          "alias",
			IdentityFile:   "identity",
			KnownHostsFile: "known-hosts",
			EntryFile:      "entry",
			ProxyFile:      "proxy",
			ConfigFile:     "config",
			HostKey:        "host-key",
		},
	}
	if err := validateConnection(connection); err == nil {
		t.Fatal("connection without sandbox UID was accepted")
	}

	managed := ManagedSandbox{
		Version:      1,
		Phase:        "bound",
		Claim:        SandboxIdentity{Context: "homelab", Namespace: "developer", Name: "sandbox", UID: "claim-uid"},
		Template:     "dev-small",
		WarmPool:     "dev-small",
		IdentityFile: "identity",
	}
	if err := validateManaged(managed); err == nil {
		t.Fatal("bound sandbox without sandbox and home identities was accepted")
	}

	retained := RetainedHome{
		Version:  1,
		State:    retainedHomeAvailable,
		Template: "dev-small",
		WarmPool: "dev-small",
		Origin:   SandboxIdentity{Context: "homelab", Namespace: "developer", Name: "sandbox", UID: "sandbox-uid"},
		Home:     PersistentHome{Name: "home-sandbox", UID: "home-uid", Capacity: "10Gi", StorageClass: "longhorn"},
	}
	if err := validateRetainedHome(retained); err != nil {
		t.Fatalf("valid retained home rejected: %v", err)
	}
	withoutTemplate := retained
	withoutTemplate.Template = ""
	if err := validateRetainedHome(withoutTemplate); err == nil {
		t.Fatal("retained home without template provenance was accepted")
	}
	deleting := retained
	deleting.State = retainedHomeDeleting
	if err := validateRetainedHome(deleting); err == nil {
		t.Fatal("deleting retained home without PV identity was accepted")
	}
	deleting.Deletion = &PersistentVolume{Name: "pv-home-sandbox", UID: "pv-uid", ReclaimPolicy: "Delete"}
	if err := validateRetainedHome(deleting); err != nil {
		t.Fatalf("valid deleting home rejected: %v", err)
	}
	retained.Home.UID = ""
	if err := validateRetainedHome(retained); err == nil {
		t.Fatal("retained home without PVC UID was accepted")
	}
}
