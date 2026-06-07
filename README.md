# MAADAT Recon — Microsoft Auto Approved DL Account Takeover Recon

> Enumerate self-joinable and attribute-exploitable groups in Microsoft Entra ID (Azure AD) from a low-privileged, assumed-breach vantage point.

---

## Overview

**MAADAT Recon** is a read-only PowerShell reconnaissance tool designed for authorized red team and assumed-breach engagements. It authenticates as a low-privileged user and enumerates:

- **Public M365 (Unified) groups** — self-joinable without owner approval
- **Dynamic membership groups** — whose membership rules key on user-mutable attributes (e.g. `department`, `jobTitle`, `extensionAttribute*`)
- **Distribution / mail-enabled security groups** — with open or approval-gated join restrictions

Each discovered group is correlated against:

- Active and PIM-eligible directory role assignments
- Conditional Access policy inclusions and exclusions
- App role grants — including resolved role names and descriptions from the resource application manifest
- Dynamic rule exploitability (guest exclusion awareness)
- Group membership (optional, via `-IncludeGroupMembers`)

Results are risk-tiered (`Critical`, `High`, `Medium`, `Low`) and exported to JSON. Optionally, high-value group `objectId`s can be exported for use with **AzureHound / BloodHound**.

A `-ProveJoin` mode allows empirical proof of exploitability by actually self-adding to a target group, with optional automatic revert.

---

## Background and Novel Attack Path

### What is Known

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

---

## Requirements

| Requirement | Notes |
|---|---|
| PowerShell 5.1+ or PowerShell 7+ | |
| `ExchangeOnlineManagement` module | Only required for distribution group enumeration; skippable via `-SkipExchange` |
| Network access to `login.microsoftonline.com` and `graph.microsoft.com` | |
| A valid user account in the target tenant | Low-privilege is sufficient for enumeration |

---

## Authentication

Authentication uses the **OAuth device code or interactive browser flow** against first-party Microsoft (FOCI) clients. No app registration is required.

| Client | AppId | Notes |
|---|---|---|
| Microsoft Office (default) | `d3590ed6-52b3-4102-aeff-aad2292ab01c` | Broad delegated Graph footprint |
| Azure CLI | `04b07795-8ddb-461a-bbee-02f9e1bf7b46` | Used automatically for Interactive auth |

### Auth Methods

| Method | Flag | Notes |
|---|---|---|
| Device Code | `-AuthMethod DeviceCode` | Default. Works where browser access is unavailable. |
| Interactive | `-AuthMethod Interactive` | Opens a browser window. Automatically uses the Azure CLI client for redirect URI compatibility. |

---

## Parameters

| Parameter | Type | Default | Description |
|---|---|---|---|
| `-TenantId` | String | `common` | Tenant domain or GUID. Required for Interactive auth. Strongly recommended for all runs. |
| `-UserPrincipalName` | String | — | UPN passed to Exchange Online `Connect-ExchangeOnline`. |
| `-FirstPartyClientId` | String | `d3590ed6-...` | FOCI client AppId to authenticate as for device code flow. |
| `-AuthMethod` | String | `DeviceCode` | Authentication method: `DeviceCode` or `Interactive`. |
| `-OutputPath` | String | `.\MAADATRecon_<timestamp>.json` | Path to write the JSON results file. |
| `-SkipExchange` | Switch | — | Skip Exchange Online connection and distribution group enumeration. |
| `-IncludeGroupMembers` | Switch | — | Enumerate and include full member lists for each discovered group in the JSON output. |
| `-IncludeBloodHoundIds` | Switch | — | Write a `.bloodhound.txt` file of Critical/High group `objectId`s alongside the JSON output. |
| `-ProveJoin` | String | — | `objectId` or `displayName` of a single group to self-join. Enables proof-of-concept mode. Mandatory when using the `Prove` parameter set. |
| `-RevertAfter` | Switch | — | When used with `-ProveJoin`, removes the account from the group after join is confirmed. |

---

## Usage Examples

### Enumeration

```powershell
# Basic run — device code auth, all defaults
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com

# Skip Exchange Online (no EXO module / permissions)
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com -SkipExchange

# Use the Azure CLI FOCI client for a broader delegated scope
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com -FirstPartyClientId 04b07795-8ddb-461a-bbee-02f9e1bf7b46

# Interactive browser auth
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com -AuthMethod Interactive

# Custom output path
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com -OutputPath "C:\Reports\contoso_recon.json"

# Include full group member lists in JSON output
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com -IncludeGroupMembers

# Include BloodHound objectId export
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com -IncludeBloodHoundIds

# Full output — members, BloodHound export, custom path
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com -IncludeGroupMembers -IncludeBloodHoundIds `
    -OutputPath "C:\Reports\contoso_recon.json"
```

### Proof of Concept (ProveJoin)

> ⚠️ **Mutating action.** `-ProveJoin` will actually add your account to the target group. Only use against tenants you are authorized to test. Every mutation is logged.

```powershell
# Self-join by objectId, then revert
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com `
    -ProveJoin "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -RevertAfter

# Self-join by display name, keep membership
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com `
    -ProveJoin "All Staff" -RevertAfter

# ProveJoin with interactive auth
.\Invoke-MAADATRecon.ps1 -TenantId contoso.com -AuthMethod Interactive `
    -ProveJoin "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -RevertAfter
```

When `-ProveJoin` is used the tool will:
1. Look up the target group directly — no full tenant enumeration is performed
2. Display current group membership before joining
3. Self-join the group
4. Re-enumerate membership, highlighting your account in **yellow** with a **`+New`** callout in green
5. Optionally revert the join if `-RevertAfter` is supplied

### Discovering Your Tenant ID

If you only know the domain, use the OpenID Connect discovery endpoint to retrieve the tenant GUID:

```powershell
$disco = Invoke-RestMethod "https://login.microsoftonline.com/contoso.com/.well-known/openid-configuration"
($disco.issuer -replace 'https://sts.windows.net/','').TrimEnd('/')
```

---

## Risk Tiers

| Tier | Criteria |
|---|---|
| **Critical** | Group has an active directory role assignment, a PIM-eligible role, or is excluded from a Conditional Access policy |
| **High** | Group is role-assignable, included in a Conditional Access policy, has app role grants, or is a dynamic group with an exploitable rule (guest not excluded) |
| **Medium** | Mail-enabled group with an open or approval-gated join restriction and no privilege signals |
| **Low** | No privilege signals identified |

> **Note:** `ApprovalRequired` distribution groups are included in results for visibility — an attacker may socially engineer approval — but are rated no higher than `Medium` absent other privilege signals.

---

## App Role Grants

When a group has been granted roles against a resource application (e.g. SharePoint, a custom API, a third-party SaaS app registered in the tenant), every member of that group inherits those grants. This is particularly relevant to the novel attack chain described above — a group configured as the identity for a SaaS application will surface here.

The tool resolves each grant fully against the resource application's service principal manifest, producing:

| Field | Description |
|---|---|
| `Resource` | Display name of the application the role was granted against |
| `ResourceId` | `objectId` of the resource service principal |
| `AppRoleId` | GUID of the specific app role granted |
| `RoleName` | Resolved display name of the role (e.g. `Sites.FullControl.All`) |
| `RoleDescription` | Full description of the role as defined in the app manifest |

A grant where `appRoleId` is `00000000-0000-0000-0000-000000000000` indicates default access — no specific role was assigned — and is labeled `Default Access`.

App role grants on any discovered group trigger a `High` risk tier rating regardless of the specific role, since the permissions within a third-party or custom application are opaque to Entra-native tooling and may be highly privileged.

---

## Output

### JSON Report

All results are written to a JSON file (default: `.\MAADATRecon_<yyyyMMdd_HHmmss>.json`).

Each entry includes:

```json
{
  "DisplayName": "All Staff",
  "ObjectId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
  "JoinVector": "Public M365 group (self-join, no approval)",
  "Mail": "allstaff@contoso.com",
  "MailEnabled": true,
  "IsRoleAssignable": false,
  "IsDynamic": false,
  "DynamicExploitable": null,
  "HasLicenses": false,
  "MemberCount": 42,
  "Members": [
    {
      "ObjectId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
      "DisplayName": "Jane Smith",
      "UserPrincipalName": "jane.smith@contoso.com",
      "UserType": "Member",
      "JobTitle": "Finance Manager",
      "Department": "Finance"
    }
  ],
  "Privilege": {
    "HasRoleAssigned": false,
    "RolesAssigned": [],
    "HasEligibleRole": false,
    "RolesEligible": [],
    "HasAppRoles": true,
    "AppRoleGrants": [
      {
        "Resource": "NetSuite",
        "ResourceId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "AppRoleId": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx",
        "RoleName": "Administrator",
        "RoleDescription": "Full administrative access to NetSuite"
      }
    ],
    "CAIncludeGroup": false,
    "CAExcludeGroup": false,
    "CAIncludes": [],
    "CAExcludes": []
  },
  "RiskTier": "High"
}
```

> `Members` and `MemberCount` are only populated when `-IncludeGroupMembers` is supplied. `MemberCount` will be `null` otherwise.

### BloodHound Export

When `-IncludeBloodHoundIds` is supplied, a second file is written alongside the JSON:

```
C:\Reports\contoso_recon.bloodhound.txt
```

This contains one `objectId` per line for all `Critical` and `High` risk groups, ready to be piped into **AzureHound** or used as input for **BloodHound** graph queries.

---

## Scope and Limitations

- The tool operates entirely within the **delegated permissions** of the chosen FOCI client. What is readable is bounded by what Microsoft has pre-consented for that client.
- CA policy enumeration requires the authenticated user to have sufficient delegated access; failures are caught and logged as warnings without halting execution.
- Exchange Online enumeration requires the `ExchangeOnlineManagement` module and sufficient EXO RBAC for the acting user. Use `-SkipExchange` if unavailable.
- Dynamic group membership rules are analyzed statically against a known list of user-mutable attributes. Rules using custom or non-standard attributes may not be flagged.
- Distribution groups without an `ExternalDirectoryObjectId` cannot be resolved via Graph; member enumeration and privilege correlation will be skipped for those groups.
- `-IncludeGroupMembers` will significantly increase runtime and output file size in large tenants. Use selectively where full membership context is needed.

---

## Legal

This tool is intended for use by authorized security professionals during sanctioned penetration tests and red team engagements only. Unauthorized use against tenants you do not have explicit written permission to test may violate computer fraud and abuse laws in your jurisdiction. The authors accept no liability for misuse.