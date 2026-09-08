# Kubeflock

Kubeflock gives Herdr users agent work environments on Kubernetes.

## Language

**Sandbox**:
A named, reusable project environment for one person, with isolated compute and its own files.
_Avoid_: Machine, pane

**Home**:
A sandbox's persistent files, including its project checkout, settings, agent history, and credentials saved by tools.
_Avoid_: Workspace

**Retained home**:
A home kept after its sandbox is deleted. A user may explicitly choose it for a replacement sandbox; a matching sandbox name does not imply reuse.
_Avoid_: Backup

**Template**:
An approved definition of the environment a new sandbox receives.
_Avoid_: Sandbox instance

**Warm pool**:
A supply of unclaimed sandboxes kept ready for allocation. A warm pool may have no sandboxes waiting.
_Avoid_: Active sandboxes

**Claim**:
A request for a sandbox from a selected warm pool.
_Avoid_: Connection

**Machine**:
A saved Herdr connection to one remote session. Removing a machine connection does not mean deleting its sandbox.
_Avoid_: Sandbox

**Disconnect**:
Detach the user's view while leaving the sandbox and its running processes intact.
_Avoid_: Stop, delete

**Stop**:
End the sandbox's compute use while retaining its files. Stopping does not promise preservation of running processes.
_Avoid_: Disconnect

**Delete**:
Remove a sandbox. Removing its stored files is a separate, explicitly confirmed decision.
_Avoid_: Disconnect
