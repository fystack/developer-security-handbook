# Developer offboarding checklist

Run the same day the person leaves (immediately for involuntary exits).

_Handbook reference: [Part VII, People & Process](../docs/07-people-and-process.md)_

## Cut access (first hour)
- [ ] Disable the SSO / identity provider account and revoke active sessions
- [ ] Remove from the GitHub org; revoke their personal access tokens, SSH keys, deploy keys and OAuth app grants
- [ ] Remove cloud access (AWS, GCP, Azure) and any IAM users or access keys
- [ ] Remove from VPN, bastion hosts, CI/CD, monitoring and on-call
- [ ] Remove from package registries (npm, PyPI, Docker Hub) and vendor SaaS
- [ ] Revoke their access to the password manager and shared vaults

## Rotate shared secrets they could read
- [ ] Database and service passwords
- [ ] API keys and webhook secrets
- [ ] Signing keys and certificates
- [ ] Shared credentials (Wi-Fi, test accounts)

## Devices and data
- [ ] Recover laptop, tokens and hardware keys
- [ ] Wipe and reimage devices
- [ ] Transfer ownership of repos, docs, dashboards and cron jobs

## Verify
- [ ] Review their last 30 days of audit logs (GitHub, cloud, VPN) for anything unusual
- [ ] Confirm they no longer appear in any access list
- [ ] Record completion in the ticket
