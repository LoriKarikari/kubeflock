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
}
