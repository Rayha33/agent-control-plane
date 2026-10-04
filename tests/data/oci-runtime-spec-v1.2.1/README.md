# Vendored OCI Runtime Specification schemas

These test-only files are copied from the Open Container Initiative Runtime
Specification tag [v1.2.1](https://github.com/opencontainers/runtime-spec/tree/v1.2.1/schema)
(commit `524fc0e1b8ab0180e2fc9abd31837a0f4ed1fd6b`). They are the upstream Draft 4 schemas and transitive
references used to validate the Linux config emitted by
`build_oci_worker_config`; no schema fields were edited. Source repository
license: Apache-2.0 (see the upstream LICENSE at the same commit).

Files included: `config-schema.json`, `config-linux.json`, `defs.json`, and
`defs-linux.json`. The unused Solaris, VM, Windows, and ZOS platform schemas
are intentionally omitted. The validator has no remote-reference fallback, so
an unexpected or missing schema reference fails instead of fetching from the
network.

Pinned SHA-256 digests:

```
2fd3af83c22f3d1420d42c139462b7f35012ceea402a9a47f090695a5aea84e2  config-schema.json
ca172a5dbe1242ddde4316cea5568130c552649569b0cc65860910949d529737  config-linux.json
9b2420b3f02970e14533f9506b6590f5b405aad8c45dd8871bd129574ee316bb  defs.json
bb1c6346f7bd683e38389ea489b730e94ad92c3030113d28499ce76bd6e5e73a  defs-linux.json
```
