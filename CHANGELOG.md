# Changelog

All notable changes to the Wazuh Helm Chart will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.0.8] - 2025-12-09 - FINAL RELEASE

### Deprecated
- **This chart is officially deprecated and no longer maintained**
- Users should migrate to [Morgoved's Wazuh Helm Chart](https://artifacthub.io/packages/helm/wazuh-helm-morgoved/wazuh)
- Repository archived and set to read-only

### Changed
- Updated Chart.yaml with deprecation notice
- Added DEPRECATION.md with migration guidance
- Added this CHANGELOG.md to document version history
- Updated README files with deprecation warnings

---

## [0.0.7] - 2024-11-XX

### Changed
- Increased Wazuh managers memory requests/limits ([cf2d960](https://github.com/promptlylabs/wazuh-helm-chart/commit/cf2d960))

### Added
- Updated Wazuh version to 4.11.1 ([57efefa](https://github.com/promptlylabs/wazuh-helm-chart/commit/57efefa))

---

## [0.0.6] - 2024-XX-XX

### Added
- Updated Wazuh version to 4.11.0 ([99a4f4e](https://github.com/promptlylabs/wazuh-helm-chart/commit/99a4f4e))

---

## [0.0.5] - 2024-XX-XX

### Fixed
- Removed quotation marks from indexer host on manager config ([f063eb8](https://github.com/promptlylabs/wazuh-helm-chart/commit/f063eb8))

---

## [0.0.4] - 2024-XX-XX

### Added
- Ability to define local internal options for Wazuh manager ([c38147b](https://github.com/promptlylabs/wazuh-helm-chart/commit/c38147b))

---

## [0.0.3] - 2024-XX-XX

### Added
- Ingresses for agent registration and communication ([6fe79a9](https://github.com/promptlylabs/wazuh-helm-chart/commit/6fe79a9))

---

## [0.0.2] - 2024-XX-XX

### Fixed
- Helm template spacing for imagePullSecrets ([6e7b8d6](https://github.com/promptlylabs/wazuh-helm-chart/commit/6e7b8d6))

---

## [0.0.1] - 2024-XX-XX

### Added
- Initial release of Wazuh Helm Chart
- Support for Wazuh Manager (Master and Worker nodes)
- Support for Wazuh Indexer (OpenSearch-based)
- Support for Wazuh Dashboard (Kibana with Wazuh plugins)
- Helm Release workflow for automated publishing ([42fe263](https://github.com/promptlylabs/wazuh-helm-chart/commit/42fe263))
- Cert-manager dependency for TLS certificate management
- Comprehensive values.yaml with configuration options
- Network policies, ingresses, and service configurations

---

## Links

- [Repository](https://github.com/promptlylabs/wazuh-helm-chart)
- [Artifact Hub](https://artifacthub.io/packages/helm/wazuh-helm/wazuh)
- [Migration Alternative - Morgoved's Chart](https://artifacthub.io/packages/helm/wazuh-helm-morgoved/wazuh)

---

**Note**: This is the final version of this chart. Version 0.0.8 marks the deprecation and end of maintenance. Please migrate to alternative solutions.
