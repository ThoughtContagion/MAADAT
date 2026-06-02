# MAADAT — Microsoft Auto-Approved DL Account Takeover

  ![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)
  ![PowerShell 7+](https://img.shields.io/badge/PowerShell-7%2B-5391FE.svg)
  ![Platform: Microsoft 365](https://img.shields.io/badge/platform-Microsoft%20365-orange.svg)

  > An assumed-breach reconnaissance tool that finds Microsoft 365 groups and distribution
  > lists a standard user can **join without approval**, then shows which of those self-joins
  > lead to **privilege escalation, Conditional Access bypass, or account takeover**.

  **Attack path discovered by [@redskycyber](https://github.com/redskycyber).** Tooling by [@ThoughtContagion](https://github.com/ThoughtContagion)

  ---

  ## ⚠️ Authorized Use Only

  **MAADAT is intended solely for authorized security assessments, penetration tests, and
  educational use against tenants you own or have explicit, documented written permission to
  test.** Self-joining groups and enumerating directory objects in a Microsoft 365 tenant
  without authorization may violate the U.S. Computer Fraud and Abuse Act (CFAA), the UK
  Computer Misuse Act, and equivalent laws worldwide, as well as your agreements with
  Microsoft.

  By using this tool you accept full responsibility for your actions. The authors provide MAADAT "as is", without warranty of any kind, and accept **no liability**
  for misuse or for any damage arising from its use. If you do not have written authorization
  for the target tenant, **do not run this tool.**

  MAADAT is **read-only by default.** The only state-changing behavior — actually joining a
  group — requires the explicit `-ProveJoin` switch, prompts for confirmation, and supports
  automatic clean-up with `-RevertAfter`.

  ---

  ## Overview

  Microsoft 365 lets group membership be **self-service**:

  - **Public Microsoft 365 (Unified) groups** can be joined by any member of the organization
    with no owner approval.
  - **Distribution lists and mail-enabled security groups** with `MemberJoinRestriction` set
    to `Open` (or loosely-governed `ApprovalRequired`) let anyone add themselves.
  - **Dynamic-membership groups** auto-add users whose attributes match a rule — and some of
    those attributes are user-editable.

  On their own these are convenience features. They become an attack path when a self-joinable
  group is also **privileged or trusted**: it holds a directory role, is excluded from an MFA
  Conditional Access policy, grants an application role, or — the case MAADAT is named for — is
  a **distribution list used as the shared login or password-reset identity for a third-party
  SaaS/ERP system**. An attacker who self-joins that list receives the password-reset email and
  takes over the downstream account.

  MAADAT runs from the perspective of an already-compromised standard (or guest) user,
  enumerates every group that user can self-join, and **correlates each one to its privilege and
  policy linkage** so you can immediately see which self-joins actually matter.

  ## What MAADAT checks

  - **Public Microsoft 365 groups** — self-join, no approval.
  - **Open / approval-required distribution lists & mail-enabled security groups** — via
    `MemberJoinRestriction`.
  - **Exploitable dynamic-membership rules** — membership rules keyed on user-editable
    attributes (`department`, `jobTitle`, `city`, `otherMails`, `extensionAttribute1-15`, etc.),
    flagged higher when they lack a `user.userType -ne "Guest"` exclusion.
  - **Privilege & policy correlation** for each joinable group:
    - role-assignable (`isAssignableToRole`)
    - active **and** PIM-eligible directory role assignments
    - Conditional Access `includeGroups` / `excludeGroups` membership (a self-joinable group in
      an MFA policy's *exclude* list is the loudest finding)
    - application role grants
  - **Tenant self-service posture** — `allowedToCreateSecurityGroups` and the Group.Unified
    group-creation settings.
  - **Shared-identity heuristic** — mail-enabled open-join groups flagged for manual review as
    possible shared-login / inbox-exposure vectors.

  ## Risk tiers

  | Tier | Meaning |
  |------|---------|
  | **Critical** | Self-joinable **and** holds an active/eligible directory role, or is excluded from an MFA/grant Conditional Access policy |
  | **High** | Self-joinable **and** role-assignable, in a CA include grant, has app-role grants, or is a dynamic group with an exploitable (non-guest-excluded) rule |
  | **Medium** | Self-joinable and mail-enabled — possible shared-identity / inbox-exposure vector (manual review) |
  | **Low** | Self-joinable with no privilege or policy linkage detected |

  ## Requirements

  - PowerShell 7+ (recommended)
  - Modules: `Microsoft.Graph` (at minimum `Microsoft.Graph.Authentication`) and
    `ExchangeOnlineManagement`
  - A standard user account in the target tenant (the "assumed breach" identity)

  Delegated Graph scopes requested:

  - Enumeration: `Group.Read.All`, `Directory.Read.All`, `Policy.Read.All`,
    `RoleManagement.Read.Directory`, `Application.Read.All`, `User.Read`
  - Proof-of-exploit (`-ProveJoin` only): `GroupMember.ReadWrite.All`

  > Exact consent behavior depends on the tenant. If a normal user cannot consent to or read a
  > given surface, MAADAT degrades gracefully and notes it — which is itself a useful signal
  > about the tenant's posture.

  ## Installation

  ```powershell
  git clone https://github.com/ThoughtContagion/MAADAT.git
  cd MAADAT
  Install-Module Microsoft.Graph, ExchangeOnlineManagement -Scope CurrentUser
  ```

  ## Usage

  ```powershell
  # Read-only enumeration (safe — performs no writes), with BloodHound pivot list:
  .\Invoke-MAADATRecon.ps1 -UserPrincipalName user@contoso.onmicrosoft.com -IncludeBloodHoundIds

  # Target a specific tenant / skip Exchange enumeration:
  .\Invoke-MAADATRecon.ps1 -TenantId <tenant-guid> -SkipExchange

  # Prove exploitability against ONE group from the report, then clean up
  # (prompts for confirmation before the only state-changing action):
  .\Invoke-MAADATRecon.ps1 -ProveJoin <groupId-or-name> -RevertAfter
  ```

  ### Output

  - A ranked console table (Critical → Low) of self-joinable groups with their join vector,
    roles, and CA linkage.
  - A full JSON report — timestamped, with the path configurable via `-OutputPath`.
  - With `-IncludeBloodHoundIds`: a companion `.bloodhound.txt` list of Critical/High group
    objectIds for pivoting in BloodHound / AzureHound.

  ## Defensive guidance

  Blue teams can close this exposure by:

  - Setting open groups to a closed join policy:
    `Set-DistributionGroup -Identity 'Group' -MemberJoinRestriction Closed`
  - Making unintended public groups private:
    `Set-UnifiedGroup -Identity 'Group' -AccessType Private`
  - Restricting self-service group management in Entra (disable "users can create security
    groups"; scope Microsoft 365 group creation to an approved group).
  - Never using self-joinable groups for directory-role assignment, Conditional Access
    inclusion/exclusion, app-role grants, or as shared login/recovery identities for external
    services.
  - For dynamic groups, avoiding user-editable attributes in membership rules and adding a
    `user.userType -ne "Guest"` exclusion.

  For continuous, tenant-wide detection, run an app-only auditor that enumerates these same
  conditions across every group rather than from a single user's vantage point.


  ## Background and Novel Attack Path

  ### What is Known
  The dynamic-membership-rule variant is well documented; the open-distribution-list self-join
  used as a **shared-SaaS-login takeover** path is, as far as public sources go, largely
  undocumented as a named technique. It was discovered by [@redskycyber](https://github.com/redskycyber) — which is why this tool exists.
  
  The individual primitives this tool covers are documented in isolation:

  - **Dynamic group rule abuse** is a named, well-understood technique. Tenable ships a dedicated [Indicator of Exposure](https://www.tenable.com/indicators/ioe/entra/DYNAMIC-GROUP-FEATURING-AN-EXPLOITABLE-RULE), Microsoft Learn [explicitly warns to audit write permissions](https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership) on attributes used in dynamic rules, and there are public writeups including [Abuse Dynamic Groups in Entra ID for Privilege Escalation](https://medium.com/@AlbertGlenn/abuse-dynamic-groups-in-entra-id-for-privilege-escalation-292652f8f49b) and a [2026 BloodHound Entra CTF walkthrough](https://medium.com/@cyberguy851/bloodhound-entra-id-ctf-2-from-guest-to-global-admin-exploiting-application-administrator-via-251d6d32e3ea) demonstrating guest → Global Admin via dynamic group chaining.

  - **Open M365 groups and `MemberJoinRestriction`** are documented as configuration settings ([distribution group management](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-distribution-groups/manage-distribution-groups), [MemberJoinRestriction property](https://learn.microsoft.com/en-us/previous-versions/office/exchange-server-api/ff337272(v=exchg.150))).

  - **Self-join → membership → inherited access** as a general principle, and group-membership-write edges as attack path primitives, are modeled in [BloodHound / AzureHound](https://posts.specterops.io/microsoft-breach-how-can-i-see-this-in-bloodhound-33c92dca4c65). [CoreView](https://www.coreview.com/blog/elevation-of-privilege-vulnerabilities) and others discuss group-object-based elevation of privilege generally.

  ### What is Novel

  While researching the open DL / open M365 group self-join vector, **no existing writeup was found** that documents the abuse of `MemberJoinRestriction = Open` as a self-service entry point into a privileged group context — only the configuration setting itself is documented, not its exploitation.

  More significantly, the following full attack chain was identified and executed empirically, and **does not appear to be documented anywhere as a named technique**:

  > **Self-join an open distribution list that is configured as the shared login or account-recovery identity for a third-party SaaS application, trigger a password reset on the SaaS account, and intercept the reset email in the now-joined shared inbox — gaining full access to the SaaS application without touching any Entra directory role or Azure resource.**

  The individual primitives (open DL, shared mailbox as SaaS identity, password reset interception) are all known. The chain — as executed — is the original finding. Existing tooling (including inspectors that look at open groups and SaaS identity separately) does not combine them into a single correlated attack path.

  This tool was built in part to surface the preconditions for this chain: an open or lightly-gated mail-enabled group that holds privileged membership in an external context not visible to Entra-only tooling.

    - [Tenable — Dynamic Group Featuring an Exploitable Rule](https://www.tenable.com/indicators/ioe/entra/DYNAMIC-GROUP-FEATURING-AN-EXPLOITABLE-RULE)
    - [Microsoft Learn — Dynamic membership rules for groups](https://learn.microsoft.com/en-us/entra/identity/users/groups-dynamic-membership)
    - [Microsoft Learn — Manage distribution groups in Exchange Online](https://learn.microsoft.com/en-us/exchange/recipients-in-exchange-online/manage-distribution-groups/manage-distribution-groups)
    - [Microsoft Learn — Set up self-service group management](https://learn.microsoft.com/en-us/entra/identity/users/groups-self-service-management)

  ## Credits

  - **Attack-path research & discovery:** [@redskycyber](https://github.com/redskycyber) —
    identified the self-service-join → shared-distribution-list → account-takeover path that
    MAADAT operationalizes.
  - **Tooling & engineering:** [@ThoughtContagion](https://github.com/ThoughtContagion)

  ## License

  Licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**. See [LICENSE](LICENSE).
  The AGPLv3 license governs copying, modification, and distribution; it does **not** grant any
  permission to test systems you are not authorized to assess — see *Authorized Use Only* above.

  ## Disclaimer

  This project is not affiliated with or endorsed by Microsoft. "Microsoft 365", "Entra", and
  related marks belong to Microsoft. Use only with explicit authorization.

  ---
