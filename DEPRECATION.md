# Deprecation Notice

## Status: DEPRECATED

This Helm chart is **no longer maintained** and has been officially deprecated as of version 0.0.8.

## Reason for Deprecation

We are no longer using Wazuh in our infrastructure and therefore cannot maintain this Helm chart with the quality and attention it deserves. Rather than provide an unmaintained solution, we're deprecating this chart to ensure users can find actively maintained alternatives.

## Timeline

- **Deprecation Date**: December 9, 2025
- **Final Version**: 0.0.8
- **Repository Status**: Archived (read-only)

## Migration Path

We recommend migrating to **Morgoved's Wazuh Helm Chart**, which is actively maintained and provides comprehensive Wazuh deployment capabilities.

### Alternative Chart

**Morgoved's Wazuh Helm Chart**
- Artifact Hub: https://artifacthub.io/packages/helm/wazuh-helm-morgoved/wazuh
- GitHub: https://github.com/morgoved/wazuh-helm

### Migration Steps

1. **Review Current Configuration**: Export your current `values.yaml` configuration
2. **Compare Charts**: Review Morgoved's chart documentation to understand configuration differences
3. **Test in Non-Production**: Deploy the new chart in a test environment first
4. **Plan Migration**: Schedule a maintenance window for the production migration
5. **Backup Data**: Ensure you have backups of your Wazuh data before migration
6. **Deploy New Chart**: Install Morgoved's chart with your adapted configuration
7. **Verify**: Confirm all agents are connected and data is flowing correctly

## What Happens Now?

- **Chart Availability**: The chart will remain available on Artifact Hub with a deprecated status
- **Repository**: This GitHub repository is now archived and read-only
- **Issues/PRs**: No new issues or pull requests can be created
- **Installation**: You can still install existing versions, but we strongly recommend migrating to an actively maintained alternative
- **Support**: No further updates or support will be provided

## Questions?

If you have questions about this deprecation, you can:
- Review Morgoved's chart documentation for migration guidance
- Check the [official Wazuh Kubernetes deployment](https://github.com/wazuh/wazuh-kubernetes) as another alternative
- Fork this repository if you wish to maintain it independently

## Thank You

Thank you to everyone who used this chart. We appreciate your trust and hope the migration to Morgoved's chart is smooth and straightforward.

---

**Maintainer Contact**: andre.gomes@promptlyhealth.com
**Last Updated**: December 9, 2025
