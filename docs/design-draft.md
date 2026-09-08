# Design discussion

The user approved this v1 scope and its 13-ticket implementation breakdown. The tickets are published in [GitHub issues](https://github.com/LoriKarikari/kubeflock/issues), with acceptance criteria, the `ready-for-agent` label, and native blocking relationships. No implementation code has been committed or pushed.

Start with [Configure and check a cluster, #1](https://github.com/LoriKarikari/kubeflock/issues/1). Work only tickets whose blockers are complete.

## Agreed

- Kubernetes is the focus. Build a Go plugin for Herdr's native machine support, without herdr-mirror.
- Provide both Herdr actions and CLI commands.
- Kubernetes Agent Sandbox is required. Guided setup may install it with approval or reuse an existing installation without taking ownership.
- Require gVisor for the first release. Installing it on nodes remains an administrator task.
- Offer a Helm chart and editable starter template. Support direct Helm installation and generated values for GitOps.
- The chart owns Kubeflock's namespace, permissions, policies, templates, and warm pools. Installing the Agent Sandbox controller is optional.
- Daily plugin actions must not overwrite GitOps-managed infrastructure.
- Prefer zero warm standbys by default, with prewarming as an explicit option.
- Prefer API-only SSH access if verification supports it. Do not require Cilium, NetBird, a specific registry, or homelab addresses in the product defaults.
- Disconnect leaves processes running. Stop retains files but not necessarily processes. Deleting stored files needs separate confirmation.
- A sandbox is a named, reusable project environment, not a new environment for every task.
- Sandboxes are personal in the first release, including on shared clusters.
- The starter image includes Herdr, Pi, Git, and essential development tools. Custom images are supported. Credentials remain separate from images.
- The working checkout lives in the sandbox. Herdr provides the live agent view; users may open remote files through an SSH-capable editor. Continuous local-directory synchronization is outside the first release.
- Users authenticate inside the sandbox by default. Existing Kubernetes Secrets may be selected explicitly for automation. Never copy workstation credentials automatically or forward the workstation's SSH agent.
- Compute stops only on an explicit stop action in the first release. No automatic idle shutdown; closing Herdr only disconnects.
- Users select named administrator-defined templates. Images and resource settings belong in Helm/GitOps-managed templates, not unrestricted per-create overrides.
- Persist the whole sandbox home, including project files, agent history, settings, and credentials saved by tools. Disclose credential persistence during setup.
- Repository checkout failure leaves the sandbox usable. Users may authenticate and retry, or create an empty sandbox without a repository.
- The first release uses one explicitly configured Kubernetes context and namespace. A later change to the terminal's current context must not retarget Kubeflock.
- Use a developer-specific namespace with Kubernetes permissions enforcing access. The Agent Sandbox controller may be shared.
- Template upgrades apply to new sandboxes. Existing sandboxes require an explicit upgrade or recreation; local Herdr version changes must not restart active remote agents.
- Partial creation failures remain visible with the failed step, retry, and explicit cleanup options. Retry reuses the same sandbox. Never delete stored files silently.
- Only explicitly allowlisted Kubernetes Secrets may be attached. Kubernetes permissions still enforce access. Never print secret values.
- Setup requires explicit compute and storage budgets, with suggested defaults. Active sandboxes and warm standbys count against compute limits; retained storage continues to count against the storage budget.
- Show retained homes separately and allow users to select one for a replacement sandbox. Reusing a sandbox name must not silently reuse a retained home.
- The first release must provide create, list, connect, disconnect, stop, resume, and safe deletion through both CLI commands and Herdr actions. Verify actual Pi agent status in Herdr, not only terminal process survival.

## Source checks

Agent Sandbox v1.0.1's claim controller creates a sandbox from the template when no existing sandbox or warm-pool candidate is available. Zero warm standbys therefore has an upstream cold-start path. This is a source-level finding, not a new cluster test.

- https://github.com/kubernetes-sigs/agent-sandbox/blob/v1.0.1/extensions/controllers/sandboxclaim_controller.go#L573-L582

Herdr v0.9.0 native machine add/list/disable/enable/remove passed OpenSSH ProxyCommand tests over Docker exec and, after the user cleared an OIDC cache lock and logged in, the Kubernetes API. Disable/enable/remove preserved a running pane process. The client refused a v0.7.4 server upgrade without interactive approval and left that server unchanged.

An approved test in namespace `kubeflock-check` verified suspend/resume on gVisor with a 1Gi Longhorn home. The replacement pod reused the same PVC/PV; file and host-key hashes matched, and native machine setup succeeded again. After the user upgraded local Herdr to v0.9.0, the test sandbox was resumed and registered in their real catalog as `Kubeflock test`. It remains running for inspection.

See [the feasibility checks](feasibility-2026-09-07.md) for commands, evidence, and remaining tests.

- https://github.com/herdrdev/herdr/blob/v0.9.0/src/remote/attach.rs#L402-L415
- https://github.com/herdrdev/herdr/blob/v0.9.0/docs/next/website/src/content/docs/connecting-machines.mdx

Herdr machine profiles target one remote session. Disabling or removing a profile leaves remote sessions running. Adding a machine may require approval to install or replace a remote server; replacement can stop pane processes. Native Windows multi-machine support is not supported in these release docs.

## Still open

- Determine the minimum RBAC permissions for the verified API-only SSH path.
- Verify claim/warm-pool ownership with persistent homes. The passing cluster test used a direct Sandbox and independently owned PVC.
- Design and test deletion that retains storage. Generated PVCs carry Sandbox owner references, so plain deletion can delete the home through garbage collection.
- Test the native Herdr TUI and interactive approval behavior. The compatible add path and noninteractive refusal path passed isolated tests.
- Investigate why Herdr omitted foreground-process details under gVisor. Direct process checks proved survival, but complete agent detection parity remains unverified.
- Select supported dependency versions, chart packaging, and initial budget suggestions from those findings.

Implementation follows the approved tickets. Any further cluster changes, upgrades, or storage deletion need explicit approval beyond the tests already authorized.
