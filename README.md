# Wazuh Helm Chart

![Version: 0.0.7](https://img.shields.io/badge/Version-0.0.7-informational?style=flat-square)
![AppVersion: 4.11.1](https://img.shields.io/badge/AppVersion-4.11.1-informational?style=flat-square)
[![Artifact Hub](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/wazuh-helm)](https://artifacthub.io/packages/helm/wazuh-helm/wazuh)

Wazuh is a free and open source security platform that unifies XDR and SIEM protection for endpoints and cloud workloads.

## Get Helm Repository Info

```bash
helm repo add wazuh-helm https://promptlylabs.github.io/wazuh-helm-chart/
helm repo update
```

## Install Helm Chart

```bash
helm install [RELEASE_NAME] wazuh-helm/wazuh
```

## Information

The Helm Chart installs the following components:

- [Wazuh Dashboard](https://documentation.wazuh.com/current/getting-started/components/wazuh-dashboard.html)
- [Wazuh Indexer](https://documentation.wazuh.com/current/getting-started/components/wazuh-indexer.html)
- [Wazuh Manager](https://documentation.wazuh.com/current/getting-started/components/wazuh-server.html) (Master and Worker nodes)

HTTPS communication between components is enabled by default and set up using self-signed certificates, provided by [cert-manager](https://cert-manager.io/).

## Configuration

### Wazuh Manager

The [`ossec.conf`](http://documentation.wazuh.com/current/user-manual/reference/ossec-conf/) file is the main configuration file on the Wazuh manager. It is created on the `_helpers.tpl` file and passed via `values.yaml`.

This configuration can be replaced, by setting a different value for `wazuh.master.conf` and `waazuh.worker.conf` in the `values.yaml` file. Or extra parameters can be appended to the configuration file by setting the `wazuh.master.extraConf` and `wazuh.worker.extraConf` values.

```yaml
wazuh:
  master:
    conf: |
      <ossec_config>
        ...
    extraConf: |
      ...
```

### Wazuh Indexer

The Wazuh Indexer has 2 configuration files: `opensearch` and `internalUsers`. These files are created on the `_helpers.tpl` file and passed via `values.yaml` and can also be replaced by setting a different value for `indexer.config.opensearch` and `indexer.config.internalUsers` in the `values.yaml` file.

```yaml
indexer:
  config:
    opensearch: |
      ...
    internalUsers: |
      ...
```

### Wazuh Dashboard

The Wazuh Dashboard has [1 configuration file](https://documentation.wazuh.com/current/user-manual/wazuh-dashboard/settings.html). This file is created on the `_helpers.tpl` file and passed via `values.yaml` and can also be replaced by setting a different value for `dashboard.config` in the `values.yaml` file.

```yaml
dashboard:
  config: |
    ...
```

## Contributing

Feel free to contact the maintainer of this repository for any questions or concerns. Contributions are encouraged and appreciated.