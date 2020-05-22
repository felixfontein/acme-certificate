# Changelog for acme_certificate

## Version 1.1.1 (2020-05-22)

- Linting, to make Galaxy more happy. (ansible-lint does not like missing modules. This might get better with collections.)

## Version 1.1.0 (2020-05-22)

- Added better namespacing for role parameters; all role parameters now start with `acme_certificate_`. The old, shorter names can still be used for now. Support for them will be dropped in version 2.0.0, to be released later this year.
- Dropped support for GCDNS (which never worked).
- Support for DNS provider NS1 for DNS challenges (thanks to @timelapserduck).
- Lint YAML files (thanks to @pgporada).
- Allow `key_path` to not have trailing slash (thanks to @nwmcsween).
- Fix curve used for P-256.
- Require Ansible 2.8.3.

## Version 1.0 (2019-07-01)

First version published on Ansible Galaxy.
