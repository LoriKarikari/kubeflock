# Domain documentation and contracts

## Read before changing domain behavior

Read [CONTEXT.md](../../CONTEXT.md) for Kubeflock's vocabulary. Use its terms in code, tests, issues, and documentation.

If `docs/adr/` exists, read decisions relevant to the change. Flag conflicts with an existing decision rather than silently overriding it. Create ADRs only when a resolved trade-off needs a lasting explanation.

Keep `CONTEXT.md` a glossary. Put implementation decisions in ADRs, not in term definitions.

## Lifecycle and security contracts

- Treat saved state as untrusted input and a persisted compatibility contract. Preserve supported older records when changing its shape.
- Preserve UID and ownership checks around lifecycle and storage operations. A resource with the same name but a different UID is a replacement, not the saved resource.
- Preserve saved SSH host-key pins and connected identity files. Report mismatches rather than overwriting the saved identity.
- Keep credential values out of command arguments, logs, images, and local state. The existing delivery path uses Pod exec standard input; local records contain aliases, not secret values.
- Keep the namespace trust model explicit. Credential aliases select approved references; they do not isolate users or individual keys within an authorized Secret.
