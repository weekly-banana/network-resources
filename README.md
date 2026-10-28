# Network resources

Public, signed address directory for Shepot native clients.

The stable client URL is:

https://raw.githubusercontent.com/weekly-banana/network-resources/main/assets/route-index.json

The directory contains public API hostnames and a P-256 signature. It contains no subscription keys, account data, device identifiers or private signing keys. Clients must verify the signature and reject older or conflicting versions before using the hostnames.

## Automatic refresh

The Refresh signed directory workflow checks the existing public sources approximately every 15 minutes. GitHub may delay scheduled runs. Only a valid, newer signed directory replaces the current one; errors preserve the last verified file. Run the workflow manually from Actions when an immediate check is needed.

A small public verification status is committed once per week so an unchanged directory does not leave the repository inactive. If GitHub disables Actions or the owner account, automatic refresh needs operator attention. The last published directory remains available.

To change domain names, update and sign a higher directory version on the existing operator backend. Do not edit the mirrored JSON manually. The scheduled job will copy the validated update to the same client URL.

The workflow uses a short-lived repository-scoped GITHUB_TOKEN. No personal token or backend credentials are required.
