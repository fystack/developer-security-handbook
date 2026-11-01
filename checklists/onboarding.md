# Developer onboarding checklist

Copy this into a ticket for each new hire. Tick items off with their owner.

_Handbook reference: [Part VII, People & Process](../docs/07-people-and-process.md)_

## Device
- [ ] Managed laptop with full-disk encryption on
- [ ] Automatic OS and browser updates on
- [ ] Screen lock after 5 minutes or less
- [ ] EDR agent installed
- [ ] Host firewall on

## Identity
- [ ] SSO account created
- [ ] Password manager installed; master passphrase set
- [ ] Two hardware security keys (or passkeys) enrolled on SSO, email and password manager
- [ ] Recovery codes stored in the password manager
- [ ] Carrier port-out PIN set
- [ ] SMS removed as an MFA method where possible

## Source control
- [ ] GitHub org invite accepted; MFA enforced
- [ ] SSH key created (hardware-backed if possible)
- [ ] Commit signing enabled and verified on a test commit
- [ ] Secret-scanning pre-commit hook installed

## Access
- [ ] Access granted by role, with a ticket and an owner for each system
- [ ] No production or admin access by default (request via JIT)
- [ ] VPN or access proxy set up with MFA

## Awareness
- [ ] Read the handbook "10 highest-impact actions"
- [ ] Knows how to report a suspicious file, link or message
- [ ] Knows the security contact and incident channel
- [ ] Understands the rules for AI tools (approvals on, no secrets in prompts)
