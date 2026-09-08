# Kubeflock lint rules

The rules in this directory come from [dmmulroy/anti-slop](https://github.com/dmmulroy/anti-slop), commit `e8c4880471b23ab7f216fba7b27d173a6ef07d4c`. The upstream MIT license is preserved. Plugin names are adapted for Kubeflock. Rule implementations are unchanged.

`oxlint.config.ts` enables all generic rules and the Effect rule group. The Effect rule checks relative service-constructor imports, not package aliases. Generated output and the vendored plugin are excluded from linting.

Keep `oxlint` and `@oxlint/plugins` pinned to the same exact version. To update the rules, compare the upstream source with the vendored copy and preserve the license. Run `npm run lint` and `npm test` after updating.
