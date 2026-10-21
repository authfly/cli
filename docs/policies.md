# Policy packs

> **Not legal advice.** The packs set technical defaults and render document *templates* with `[BRACKETS]` to fill.
> Every rendered document starts with a not-legal-advice banner. Have counsel review before you rely on them.

`authfly init --policy gdpr|us-pii|ru-152fz|none` picks a pack, stored as `policy.pack` in `authfly.yaml`. On every
`authfly deploy` the pack does three things:

1. **Renders documents** into `.authfly/legal/*.md`. The server serves them at `/legal/{name}` (AUTHFLY_LEGAL_DIR).
2. **Sets server behaviour.** It sets the consent label on sign-up (AUTHFLY_TERMS_LABEL) and the extra consent kinds
   recorded with the account (AUTHFLY_EXTRA_CONSENTS). It also sets the consent version (AUTHFLY_CONSENT_VERSION) and
   the audit retention.
3. **Adds `authfly doctor` checks.** The documents must be served, and the audit log must hold no IP addresses.
   With `host_country` set, the pack also checks residency: the declared country, and that no external store is
   configured.

All packs share these endpoints, implemented and covered by `e2e/gdpr.test.ts`:

| Right | Endpoint |
|---|---|
| access / portability | `GET /api/v1/me/export`, account widget "Download" (format `authfly-export/1`: Stalwart account without credentials, Authfly records, audit trail, mailbox) |
| erasure | `DELETE /api/v1/me` (re-enter the password). Verified afterwards: Stalwart account and mailbox gone, sessions revoked, address removed from store and audit log, pseudonym kept |
| operator-side | console export and erasure (typed confirmation), logged in both audit logs |

## gdpr — Regulation (EU) 2016/679

Source: <https://eur-lex.europa.eu/eli/reg/2016/679/oj>

| Setting | Value | Article |
|---|---|---|
| Documents | `privacy` (Art. 13 notice), `dpa` (Art. 28(3) template), `records-of-processing` (Art. 30) | Art. 13, 28, 30 |
| Sign-up consent | "I accept the terms and the privacy notice (…/legal/privacy)" plus a version record | Art. 7(1) (demonstrate consent) |
| IP addresses | none in the Authfly audit log | Art. 5(1)(c) minimisation |
| Audit retention | 365 days, then pseudonymised subject | Art. 5(1)(e) |
| Response time (stated in docs) | 1 month, extendable by 2 | Art. 12(3) |
| Breach notice (reminder) | 72 h to the supervisory authority | Art. 33 |
| Reminders printed by `deploy` | Chapter V transfers (Art. 44–49) if hosted outside the EU/EEA; DPAs with processors | |

## us-pii — CCPA as amended by CPRA (Cal. Civ. Code §1798.100 et seq.)

Source: <https://leginfo.legislature.ca.gov/faces/codes_displayText.xhtml?lawCode=CIV&division=3.&title=1.81.5.&part=4.>

| Setting | Value | Section |
|---|---|---|
| Documents | `privacy` (privacy policy plus notice at collection, with a retention per category), `dpa` (service-provider contract) | §1798.100(a)(3), §1798.100(d), §1798.140(ag) |
| Sign-up consent | terms plus a privacy policy that includes the notice at collection | §1798.100(a) |
| Rights listed | know (§1798.110), delete (§1798.105), correct (§1798.106), opt-out (§1798.120), limit (§1798.121), non-discrimination (§1798.125) | |
| Response time | 45 days, plus one 45-day extension | §1798.130(a)(2) |
| `policy.us_states` | Recorded in the policy and the reminders. **Only California is verified**; other state laws (VA, CO, CT, TX, …) are **UNVERIFIED** | |
| Thresholds | §1798.140(d) revenue threshold is CPI-adjusted. The **current amount is UNVERIFIED** | §1798.140(d) |
| Breach (reminder) | §1798.82, "most expedient time possible"; other states **UNVERIFIED** | |

## ru-152fz — Federal Law No. 152-FZ "On Personal Data"

Official publication: <http://pravo.gov.ru/proxy/ips/?docbody=&nd=102108261>

| Setting | Value | Article |
|---|---|---|
| Documents | `privacy` (processing policy, in Russian), `pd-consent` (a **separate** consent document), `dpa` (operator's instruction, Art. 6 part 3) | Art. 18.1 part 2; Art. 9 part 1 |
| Sign-up consent | label in Russian; records **two** consents: `terms` and `pd_processing` | Art. 9 |
| Residency | `policy.host_country: RU` is required by the wizard for this pack. The doctor checks the declaration and that all stores are local | Art. 18 part 5 (localisation) |
| IP addresses | none in the Authfly audit log | Art. 5 part 7 |
| Response time (in the policy text) | 10 working days, +5 with a reasoned notice | Art. 20 |
| Breach (reminder) | Roskomnadzor 24 h / 72 h | Art. 21 part 3.1 |
| Reminders | Roskomnadzor notification **before** processing (Art. 22); cross-border notice (Art. 12) | |

The dates of the amendments quoted in the reminders are taken from the pack text and are **UNVERIFIED** here:
the separate-consent rule from 2025-09-01 (156-FZ) and the localisation wording from 2025-07-01 (23-FZ).

## What a pack does not do

- It does not file anything: no Roskomnadzor notification, no DPA signature, no records kept for you.
- It does not decide where you host. Residency is a declaration plus a doctor check, not an enforcement.
- It does not keep IP addresses out of Stalwart's own logs. The pack is a statement plus the doctor check on the
  Authfly audit log; keep Stalwart log retention short.
