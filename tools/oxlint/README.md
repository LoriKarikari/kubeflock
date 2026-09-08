# Kubeflock lint rules

The rules in this directory come from [dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop), commit `e8c4880471b23ab7f216fba7b27d173a6ef07d4c`. The upstream MIT license is preserved. Plugin names are adapted for Kubeflock. Rule implementations are unchanged.

`oxlint.config.ts` enables all generic rules and the Effect rule group. The Effect rule checks relative service-constructor imports, not package aliases. Generated output and the vendored plugin are excluded from linting.

## Built-in checks

Oxlint also rejects explicit `any`, focused tests, and incomplete `expect` calls. These use native rules, not custom implementations. Vitest's default checks remain enabled except `no-conditional-expect`, because command-specific assertions legitimately branch on the command being checked.

The [Kody PR](https://github.com/kentcdodds/kody/pull/2090) informed this selection. Its route-specific rules and repository-wide UI-copy scanner are not included. Custom rules stay in individual files under `rules/` and `effect/rules/`.

## Updates

Keep `oxlint` and `@oxlint/plugins` pinned to the same exact version. To update the rules, compare the upstream source with the vendored copy and preserve the license. Run `npm run lint` and `npm test` after updating.
