# Related projects

Kubeflock overlaps with remote development tools and coding-agent sandbox tools. These notes compare documented scope, not tested integrations or security guarantees.

## DevPod

The closest match to the proposed connection and workspace model. DevPod provisions devcontainer workspaces through providers, including Kubernetes. It connects through the Kubernetes control plane, starts an SSH server over the tunnel, and connects a local editor to the remote files. Its Kubernetes driver supports persistent storage.

DevPod already implements the API-tunneled SSH approach we tested. A DevPod workspace with Herdr installed is worth comparing with Kubeflock before adding more provisioning code. Compatibility with saved Herdr machines still needs testing. DevPod's documented model does not establish use of Kubernetes Agent Sandbox Claims, Templates, or WarmPools.

Sources:
- https://devpod.sh/docs/how-it-works/overview
- https://github.com/loft-sh/devpod-provider-kubernetes
- https://devpod.sh/docs/developing-providers/driver
- https://devpod.sh/docs/developing-in-workspaces/credentials

## AgentBox

`madarco/agentbox` provides isolated environments for coding agents and already documents a Herdr integration. It supports local Docker, remote Docker, and cloud providers. Its README describes copying project files and agent settings, persistent shells, checkpoints, and detach/attach commands. The checked README does not list a Kubernetes provider.

This is the closest comparison for the Herdr-facing user experience. Do not confuse it with unrelated projects also named AgentBox.

Sources:
- https://github.com/madarco/agentbox
- https://agent-box.sh/docs/integrations-herdr

## Coder

Coder provides centrally managed developer workspaces. Terraform templates can provision Kubernetes workspaces, and its workspace agent provides SSH and editor connectivity. This covers much of the broader development-platform problem, beyond the planned small Herdr plugin.

Sources:
- https://coder.com/docs/index
- https://coder.com/docs/admin/templates/extending-templates
- https://coder.com/docs/reference/cli/ssh

## Paddock

Paddock provisions per-user coding-agent sandboxes on Kubernetes. Its focus is governance: model budgets, controlled egress, tool/MCP policy, and auditing. Its documented file workflow uploads a local working directory and pulls edits back, unlike our chosen remote-checkout default. It does not replace or orchestrate the agent itself.

Source:
- https://github.com/ViktorWelbers/paddock

## Implication for Kubeflock

Remote coding environments and API-only SSH already exist. Kubeflock's proposed scope is the specific combination of Kubernetes Agent Sandbox, required gVisor isolation, and native Herdr machines. Keep it a small integration rather than duplicating a complete development platform. If the Agent Sandbox requirement changes, compare DevPod plus Herdr before building a replacement for existing tooling.
