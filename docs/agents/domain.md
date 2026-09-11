# Domain documentation and contracts

## Read before changing domain behavior

Read [CONTEXT.md](../../CONTEXT.md) for Kubeflock's vocabulary. Use its terms in code, tests, issues, and documentation.

If `docs/adr/` exists, read decisions relevant to the change. Flag conflicts with an existing decision rather than silently overriding it. Create ADRs only when a resolved trade-off needs a lasting explanation.

Keep `CONTEXT.md` a glossary. Put implementation decisions in ADRs, not in term definitions.

## Lifecycle and security contracts

- Disconnect and CLI exit leave the sandbox running. Stop preserves its allocation and home; resume reconnects it to Herdr.
- `sandbox delete NAME` permanently deletes the sandbox and its workspace storage. Require `DELETE` confirmation, interactively or through `--confirm DELETE`. Do not describe deletion as home retention.
- There is no supported restore or separate home-deletion command. Retained-home records support legacy storage cleanup and interrupted permanent deletion, not restoration.
- Treat saved state as untrusted input and a persisted compatibility contract. Preserve supported older records when changing its shape.
- Preserve UID and ownership checks around lifecycle and storage operations. A resource with the same name but a different UID is a replacement, not the saved resource.
- Preserve saved SSH host-key pins and connected identity files. Report mismatches rather than overwriting the saved identity.
- Keep the private SSH key on the workstation. Configure only its public key in the sandbox template.
- Users authenticate providers inside the sandbox. Pi may save credentials in `/home/agent/.pi/agent/auth.json`, which persists with the home. Kubeflock does not supply approved credential aliases or deliver Secret values through Pod exec.
- Keep provider credentials out of command arguments, logs, images, and workstation Kubeflock state. Treat OAuth redirect URLs as credentials. See [sandbox image authentication](../../sandbox-image/README.md).
- Keep the namespace trust model explicit. Authorized subjects can access each other's sandbox processes and homes. Use separate namespaces when that shared access is unacceptable.
