<#
  Active Directory LDAP collector (read-only) - Windows pivot edition.

  Purpose
    Perform ONLY read-only LDAP searches against a domain controller and write the raw results
    to a JSON file. It does NO analysis, NO scoring, NO report rendering, and NOTHING is written
    back to the directory. The JSON is taken off-host and processed on a Linux box with:
        k1rby offline <dump.json> -o <CLIENT>-AD-Assessment.xlsx
    which produces the xlsx + HTML + findings from the existing engine. Keeping analysis off the
    pivot is deliberate: the smaller the on-host footprint, the fewer behaviours an endpoint
    control can act on. This script uses only built-in .NET (System.DirectoryServices.Protocols),
    no modules, no compilation (no Add-Type -TypeDefinition / csc.exe), no reflection, and no
    network download. Run it from disk (sign it if you have a cert). It is intended for AUTHORIZED
    assessments only; deconflict the characteristic LDAP activity with the client's blue team
    (source-IP allowlist + timebox) - this tool does not and should not try to make the queries
    themselves quieter.

  Usage
    .\collect.ps1 -Domain corp.local -Server 10.0.0.10 -Username user -Password 'pass' -Out corp-dump.json
    .\collect.ps1 -Domain corp.local -Server dc01.corp.local            # current Kerberos context
    (add -Ssl for LDAPS/636; -Port to override; use the DA account for full LAPS/SD coverage)

  Read-only by construction: the only request type issued is SearchRequest. No Add/Modify/Delete.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$true)][string]$Domain,
  [Parameter(Mandatory=$true)][string]$Server,
  [string]$Username,
  [string]$Password,
  [string]$Out,
  [string]$Base,
  [switch]$Ssl,
  [int]$Port
)

$ErrorActionPreference = 'Stop'
if (-not $Out)  { $Out  = "$Domain-dump.json" }
# Resolve -Out to an ABSOLUTE path against the caller's PowerShell location. .NET's
# System.IO (used to write the dump) resolves relative paths against [Environment]::CurrentDirectory,
# which does NOT track Set-Location/cd in a long-lived (esp. elevated) session - so a relative -Out
# would silently land in a stale dir (often C:\Windows\System32). GetUnresolvedProviderPathFromPSPath
# handles not-yet-existing files and resolves against $PWD, keeping .NET and PowerShell in agreement.
$Out = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Out)
if (-not $Base) { $Base = 'DC=' + ($Domain -split '\.' -join ',DC=') }
if (-not $Port) { $Port = if ($Ssl) { 636 } else { 389 } }

Add-Type -AssemblyName System.DirectoryServices.Protocols

$SC  = [System.DirectoryServices.Protocols.SearchScope]
function W([string]$m){ [Console]::Error.WriteLine("[*] $m") }

# ---- bind (Negotiate = Kerberos/NTLM; read-only; supplied creds or current context) -----------
$ident = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Server, $Port)
if ($Username) {
  $cred = New-Object System.Net.NetworkCredential($Username, $Password, $Domain)
  $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($ident, $cred)
} else {
  $conn = New-Object System.DirectoryServices.Protocols.LdapConnection($ident)
}
$conn.AuthType = [System.DirectoryServices.Protocols.AuthType]::Negotiate
$conn.SessionOptions.ProtocolVersion = 3
if ($Ssl) { $conn.SessionOptions.SecureSocketLayer = $true }
$conn.Bind()
W "bound to $Server`:$Port (read-only) base=$Base"

# ---- helpers ----------------------------------------------------------------------------------
function Get-Sid([byte[]]$b){
  try { (New-Object System.Security.Principal.SecurityIdentifier($b,0)).Value } catch { '' }
}

# Convert one entry to an ordered dict keyed by the REQUESTED attribute names (stable casing),
# plus _dn. $Sid = attrs to render as S-1-5-... ; $Present = attrs we only need truthiness for.
function Convert-Entry($entry, [string[]]$attrs, [string[]]$Sid, [string[]]$Present){
  $o = [ordered]@{ _dn = [string]$entry.DistinguishedName }
  foreach ($name in $attrs) {
    if (-not $entry.Attributes.Contains($name)) { continue }
    $a = $entry.Attributes[$name]
    if ($Sid -contains $name) {
      $vals = @(); foreach ($bv in $a.GetValues([byte[]])) { $vals += (Get-Sid $bv) }
      $o[$name] = if ($vals.Count -gt 1) { $vals } else { [string]$vals[0] }
    } elseif ($Present -contains $name) {
      $o[$name] = 'present'
    } else {
      $vals = @(); foreach ($i in 0..($a.Count-1)) { $vals += [string]$a[$i] }
      $o[$name] = if ($vals.Count -gt 1) { $vals } else { [string]$vals[0] }
    }
  }
  $o
}

# Cookie-paged SUBTREE search -> array of raw SearchResultEntry.
function Search-Paged([string]$base, [string]$filter, [string[]]$attrs){
  $req = New-Object System.DirectoryServices.Protocols.SearchRequest($base, $filter, $SC::Subtree, $attrs)
  $prc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl(500)
  [void]$req.Controls.Add($prc)
  $out = New-Object System.Collections.ArrayList
  while ($true) {
    $resp = $conn.SendRequest($req)
    foreach ($e in $resp.Entries) { [void]$out.Add($e) }
    $cook = $null
    foreach ($ctl in $resp.Controls) {
      if ($ctl -is [System.DirectoryServices.Protocols.PageResultResponseControl]) { $cook = $ctl.Cookie }
    }
    if (-not $cook -or $cook.Length -eq 0) { break }
    $prc.Cookie = $cook
  }
  ,$out
}

# BASE-scoped single search -> the one entry (or $null).
function Search-Base([string]$base, [string[]]$attrs, [string]$filter='(objectClass=*)'){
  try {
    $req = New-Object System.DirectoryServices.Protocols.SearchRequest($base, $filter, $SC::Base, $attrs)
    $resp = $conn.SendRequest($req)
    if ($resp.Entries.Count -gt 0) { return $resp.Entries[0] }
  } catch { }
  return $null
}

function Collect([string]$label, [string]$base, [string]$filter, [string[]]$attrs,
                 [string[]]$Sid=@(), [string[]]$Present=@()){
  $rows = New-Object System.Collections.ArrayList
  try {
    foreach ($e in (Search-Paged $base $filter $attrs)) {
      [void]$rows.Add((Convert-Entry $e $attrs $Sid $Present))
    }
  } catch { W "$label failed: $($_.Exception.Message)" }
  W "$label : $($rows.Count)"
  ,$rows
}

$dump = [ordered]@{
  meta = [ordered]@{
    domain = $Domain; base = $Base; dc = $Server
    collectedAt = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    collector = 'collect.ps1'
  }
}

# ---- RootDSE / forest -------------------------------------------------------------------------
$rootAttrs = @('rootDomainNamingContext','forestFunctionality','domainFunctionality',
               'domainControllerFunctionality','schemaNamingContext','namingContexts','dnsHostName')
$rd = Search-Base '' $rootAttrs
$rootdse = [ordered]@{}
if ($rd) {
  foreach ($n in $rootAttrs) {
    if (-not $rd.Attributes.Contains($n)) { continue }
    $a = $rd.Attributes[$n]; $vals = @(); foreach ($i in 0..($a.Count-1)) { $vals += [string]$a[$i] }
    $rootdse[$n] = if ($vals.Count -gt 1) { $vals } else { [string]$vals[0] }
  }
}
$dump.rootdse = $rootdse

# ---- domain head (BASE) -----------------------------------------------------------------------
$domAttrs = @('minPwdLength','maxPwdAge','minPwdAge','lockoutThreshold','lockoutDuration',
              'pwdHistoryLength','pwdProperties','ms-DS-MachineAccountQuota','objectSid','msDS-Behavior-Version')
$de = Search-Base $Base $domAttrs '(objectClass=domain)'
$dump.domain = if ($de) { ,@(Convert-Entry $de $domAttrs @('objectSid') @()) } else { @() }

# ---- FSMO (5 BASE reads of fSMORoleOwner, keyed by the exact base DN) --------------------------
$fsmoBases = @($Base,
               "CN=RID Manager`$,CN=System,$Base",
               "CN=Infrastructure,$Base",
               "CN=Schema,CN=Configuration,$Base",
               "CN=Partitions,CN=Configuration,$Base")
$fsmo = [ordered]@{}
foreach ($b in $fsmoBases) {
  $e = Search-Base $b @('fSMORoleOwner')
  $fsmo[$b] = if ($e -and $e.Attributes.Contains('fSMORoleOwner')) { [string]$e.Attributes['fSMORoleOwner'][0] } else { '' }
}
$dump.fsmo_owners = $fsmo

# ---- DC servers (for site mapping) ------------------------------------------------------------
$dcsrv = New-Object System.Collections.ArrayList
try {
  foreach ($e in (Search-Paged "CN=Sites,CN=Configuration,$Base" '(objectClass=server)' @('cn'))) {
    $cn = if ($e.Attributes.Contains('cn')) { [string]$e.Attributes['cn'][0] } else { '' }
    [void]$dcsrv.Add([ordered]@{ _dn = [string]$e.DistinguishedName; cn = $cn })
  }
} catch { }
$dump.dc_servers = $dcsrv

# ---- SUBTREE buckets (same filters/attrs k1rby's live collector uses) -------------------------
$dump.fgpp = Collect 'FGPP' "CN=Password Settings Container,CN=System,$Base" `
  '(objectClass=msDS-PasswordSettings)' `
  @('name','msDS-PasswordSettingsPrecedence','msDS-MinimumPasswordLength','msDS-LockoutThreshold','msDS-PasswordHistoryLength','msDS-PSOAppliesTo',
    'msDS-MaximumPasswordAge','msDS-MinimumPasswordAge','msDS-PasswordComplexityEnabled','msDS-PasswordReversibleEncryptionEnabled','msDS-LockoutObservationWindow','msDS-LockoutDuration')

$dump.domain_controllers = Collect 'DomainControllers' $Base `
  '(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))' `
  @('name','dNSHostName','operatingSystem','operatingSystemVersion','lastLogonTimestamp','objectSid') `
  @('objectSid')

$dump.trusts = Collect 'Trusts' $Base '(objectClass=trustedDomain)' `
  @('trustPartner','trustDirection','trustType','trustAttributes')

$dump.users = Collect 'Users' $Base '(&(objectCategory=person)(objectClass=user))' `
  @('sAMAccountName','userPrincipalName','displayName','givenName','initials','sn','co',
    'userAccountControl','adminCount','servicePrincipalName','pwdLastSet','lastLogonTimestamp',
    'logonCount','whenCreated','whenChanged','memberOf','description','info','userWorkstations',
    'msDS-AllowedToDelegateTo','objectSid','sIDHistory','primaryGroupID','accountExpires','mail',
    'manager','department','title','company','mobile','homeDirectory','profilePath','scriptPath',
    'msDS-SupportedEncryptionTypes','msDS-KeyCredentialLink') `
  @('objectSid','sIDHistory') `
  @('msDS-KeyCredentialLink')

$dump.computers = Collect 'Computers' $Base '(objectClass=computer)' `
  @('name','sAMAccountName','dNSHostName','operatingSystem','operatingSystemVersion',
    'lastLogonTimestamp','userAccountControl','pwdLastSet','whenCreated','whenChanged','objectSid',
    'sIDHistory','primaryGroupID','description','mS-DS-CreatorSID','servicePrincipalName',
    'msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-AllowedToDelegateTo',
    'msDS-KeyCredentialLink','ms-Mcs-AdmPwdExpirationTime','msLAPS-PasswordExpirationTime','msLAPS-EncryptedPassword',
    'msDS-SupportedEncryptionTypes') `
  @('objectSid','sIDHistory','mS-DS-CreatorSID') `
  @('msDS-AllowedToActOnBehalfOfOtherIdentity','msDS-KeyCredentialLink','msLAPS-EncryptedPassword')

$dump.groups = Collect 'Groups' $Base '(objectClass=group)' `
  @('name','member','adminCount','description','groupType','objectSid','sIDHistory','managedBy','whenCreated','whenChanged') `
  @('objectSid','sIDHistory')

$dump.ous = Collect 'OUs' $Base '(objectClass=organizationalUnit)' @('name','description')

$dump.gpos = Collect 'GPOs' $Base '(objectClass=groupPolicyContainer)' `
  @('displayName','gPCFileSysPath','whenCreated','whenChanged')

# GUID->name map for GPO links (cn carries the {GUID})
$dump.gpo_objs = Collect 'GPOobjs' $Base '(objectClass=groupPolicyContainer)' @('cn','displayName')

$dump.gpo_containers = Collect 'GPOcontainers' $Base `
  '(|(objectClass=organizationalUnit)(objectClass=domainDNS))' @('gPLink','gPOptions','name')

$dump.gpo_site_containers = Collect 'GPOsiteContainers' "CN=Sites,CN=Configuration,$Base" `
  '(objectClass=site)' @('gPLink','gPOptions','name')

$dump.sites = Collect 'Sites' "CN=Sites,CN=Configuration,$Base" '(objectClass=site)' `
  @('name','description','whenCreated')

$dump.subnets = Collect 'Subnets' "CN=Subnets,CN=Sites,CN=Configuration,$Base" '(objectClass=subnet)' `
  @('name','siteObject','description')

# ---- published printers (printQueue) - Authenticated-Users readable ---------------------------
$dump.printers = Collect 'Printers' $Base '(objectClass=printQueue)' `
  @('printerName','serverName','driverName','portName','location','uNCName','whenCreated')

# ---- schema extension history (schema NC) - Authenticated-Users readable ----------------------
$dump.schema_history = Collect 'SchemaHistory' "CN=Schema,CN=Configuration,$Base" `
  '(|(objectClass=classSchema)(objectClass=attributeSchema))' `
  @('name','lDAPDisplayName','objectClass','whenCreated','whenChanged')

# ---- BitLocker recovery keys (msFVE-RecoveryInformation) - DA-gated; empty on a user run -------
# Recovery passwords are confidential: readable by Domain Admins / the computer object / delegates.
$dump.bitlocker = Collect 'BitLocker' $Base '(objectClass=msFVE-RecoveryInformation)' `
  @('name','msFVE-RecoveryGuid','msFVE-VolumeGuid','msFVE-RecoveryPassword','whenCreated')

# ---- group managed service accounts (gMSA) - Authenticated-Users readable --------------------
$dump.gmsa = Collect 'gMSA' $Base '(objectClass=msDS-GroupManagedServiceAccount)' `
  @('name','sAMAccountName','dNSHostName','msDS-ManagedPasswordInterval','userAccountControl','whenCreated')

# ---- AD CS certificate templates (Config NC) - Authenticated-Users readable ------------------
$dump.cert_templates = Collect 'CertTemplates' "CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$Base" `
  '(objectClass=pKICertificateTemplate)' `
  @('name','displayName','msPKI-Certificate-Name-Flag','msPKI-Enrollment-Flag','pKIExtendedKeyUsage','msPKI-RA-Signature','whenCreated')

# ---- AD CS enrollment services / CAs (Config NC) - Authenticated-Users readable ---------------
$dump.cert_cas = Collect 'CertCAs' "CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration,$Base" `
  '(objectClass=pKIEnrollmentService)' `
  @('name','displayName','dNSHostName','cACertificateDN','certificateTemplates','flags','whenCreated')

# ---- dSHeuristics (directory-service config flags; anonymous-LDAP indicator) ------------------
$dump.ds_heuristics = Collect 'dSHeuristics' "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$Base" `
  '(objectClass=nTDSService)' @('dSHeuristics')

# ---- privileged group direct members ----------------------------------------------------------
$privGroups = @('Domain Admins','Enterprise Admins','Schema Admins','Administrators',
                'Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins',
                'Protected Users')
$priv = [ordered]@{}
foreach ($g in $privGroups) {
  try {
    $m = @()
    foreach ($e in (Search-Paged $Base "(&(objectClass=group)(cn=$g))" @('member'))) {
      if ($e.Attributes.Contains('member')) {
        $a = $e.Attributes['member']; foreach ($i in 0..($a.Count-1)) { $m += [string]$a[$i] }
      }
    }
    if ($m.Count) { $priv[$g] = $m }
  } catch { }
}
$dump.priv_members = $priv
W "PrivMembers groups: $($priv.Keys.Count)"

# ---- LAPS (only rows this account can actually read a password on) -----------------------------
$laps = New-Object System.Collections.ArrayList
try {
  $lattrs = @('name','ms-Mcs-AdmPwd','ms-Mcs-AdmPwdExpirationTime','msLAPS-Password','msLAPS-PasswordExpirationTime')
  foreach ($e in (Search-Paged $Base '(objectClass=computer)' $lattrs)) {
    if ($e.Attributes.Contains('ms-Mcs-AdmPwd') -or $e.Attributes.Contains('msLAPS-Password')) {
      [void]$laps.Add((Convert-Entry $e $lattrs @() @()))
    }
  }
} catch { W "LAPS failed: $($_.Exception.Message)" }
$dump.laps = $laps
W "LAPS readable: $($laps.Count)"

# ---- DNS (dnsNode blobs, base64 - parsed off-host) --------------------------------------------
$dnsNodes = New-Object System.Collections.ArrayList
foreach ($zb in @("CN=MicrosoftDNS,DC=DomainDnsZones,$Base",
                  "CN=MicrosoftDNS,DC=ForestDnsZones,$Base",
                  "CN=MicrosoftDNS,CN=System,$Base")) {
  try {
    foreach ($e in (Search-Paged $zb '(objectClass=dnsNode)' @('name','dnsRecord'))) {
      $recs = @()
      if ($e.Attributes.Contains('dnsRecord')) {
        foreach ($bv in $e.Attributes['dnsRecord'].GetValues([byte[]])) {
          $recs += [Convert]::ToBase64String($bv)
        }
      }
      $nm = if ($e.Attributes.Contains('name')) { [string]$e.Attributes['name'][0] } else { '' }
      [void]$dnsNodes.Add([ordered]@{ zoneBase = $zb; _dn = [string]$e.DistinguishedName; name = $nm; dnsRecord = $recs })
    }
  } catch { }
}
$dump.dns_nodes = $dnsNodes
W "DNS nodes: $($dnsNodes.Count)"

# ---- DNS zones (zone objects: name + type/aging via dNSProperty, parsed off-host) -------------
$dnsZones = New-Object System.Collections.ArrayList
foreach ($zb in @("CN=MicrosoftDNS,DC=DomainDnsZones,$Base",
                  "CN=MicrosoftDNS,DC=ForestDnsZones,$Base",
                  "CN=MicrosoftDNS,CN=System,$Base")) {
  try {
    foreach ($e in (Search-Paged $zb '(objectClass=dnsZone)' @('name','whenCreated','whenChanged'))) {
      $nm = if ($e.Attributes.Contains('name')) { [string]$e.Attributes['name'][0] } else { '' }
      $wc = if ($e.Attributes.Contains('whenCreated')) { [string]$e.Attributes['whenCreated'][0] } else { '' }
      $wh = if ($e.Attributes.Contains('whenChanged')) { [string]$e.Attributes['whenChanged'][0] } else { '' }
      [void]$dnsZones.Add([ordered]@{ _dn = [string]$e.DistinguishedName; name = $nm; whenCreated = $wc; whenChanged = $wh })
    }
  } catch { }
}
$dump.dns_zones = $dnsZones
W "DNS zones: $($dnsZones.Count)"

# ---- security descriptors: nTSecurityDescriptor (Owner+Group+DACL, base64) --------------------
# Captured raw for off-host decoding. SD-flags control = 7 omits the SACL (which needs privilege).
$acls = New-Object System.Collections.ArrayList
try {
  $sdMask = [System.DirectoryServices.Protocols.SecurityMasks]'Owner, Group, Dacl'
  $sdCtl  = New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($sdMask)
  $sreq = New-Object System.DirectoryServices.Protocols.SearchRequest($Base,
            '(|(objectClass=user)(objectClass=computer)(objectClass=group)(objectClass=organizationalUnit))',
            $SC::Subtree, @('nTSecurityDescriptor'))
  $sprc = New-Object System.DirectoryServices.Protocols.PageResultRequestControl(500)
  [void]$sreq.Controls.Add($sprc)
  [void]$sreq.Controls.Add($sdCtl)
  while ($true) {
    $sresp = $conn.SendRequest($sreq)
    foreach ($e in $sresp.Entries) {
      if ($e.Attributes.Contains('nTSecurityDescriptor')) {
        $bytes = $e.Attributes['nTSecurityDescriptor'].GetValues([byte[]])[0]
        [void]$acls.Add([ordered]@{ _dn = [string]$e.DistinguishedName; sd = [Convert]::ToBase64String($bytes) })
      }
    }
    $ck = $null
    foreach ($c in $sresp.Controls) { if ($c -is [System.DirectoryServices.Protocols.PageResultResponseControl]) { $ck = $c.Cookie } }
    if (-not $ck -or $ck.Length -eq 0) { break }
    $sprc.Cookie = $ck
  }
} catch { W "ACLs failed: $($_.Exception.Message)" }
# domain head + AdminSDHolder SDs (BASE scope) -> DCSync (SI000021) and AdminSDHolder ACL findings.
# Tagged with 'kind' so the off-host analyzer knows which object each blob belongs to.
foreach ($tgt in @(
    @{ dn = $Base; kind = 'domain' },
    @{ dn = "CN=AdminSDHolder,CN=System,$Base"; kind = 'adminsdholder' })) {
  try {
    $breq = New-Object System.DirectoryServices.Protocols.SearchRequest($tgt.dn,
              '(objectClass=*)', $SC::Base, @('nTSecurityDescriptor'))
    [void]$breq.Controls.Add((New-Object System.DirectoryServices.Protocols.SecurityDescriptorFlagControl($sdMask)))
    $bresp = $conn.SendRequest($breq)
    foreach ($e in $bresp.Entries) {
      if ($e.Attributes.Contains('nTSecurityDescriptor')) {
        $bytes = $e.Attributes['nTSecurityDescriptor'].GetValues([byte[]])[0]
        [void]$acls.Add([ordered]@{ _dn = [string]$e.DistinguishedName; kind = $tgt.kind; sd = [Convert]::ToBase64String($bytes) })
      }
    }
  } catch { W "ACL $($tgt.kind) failed: $($_.Exception.Message)" }
}
$dump.acls = $acls
W "ACLs (SD blobs): $($acls.Count)"

# ---- foreign security principals (cross-trust SIDs placed in groups) --------------------------
$dump.fsp = Collect 'ForeignSPs' "CN=ForeignSecurityPrincipals,$Base" '(objectClass=foreignSecurityPrincipal)' `
  @('name','objectSid') @('objectSid')

$conn.Dispose()

# ---- write dump -------------------------------------------------------------------------------
$json = $dump | ConvertTo-Json -Depth 8
[System.IO.File]::WriteAllText($Out, $json, (New-Object System.Text.UTF8Encoding($false)))
# $Out is absolute (resolved above), so .NET wrote it here and Test-Path/Get-Item agree. Report
# defensively: a stat hiccup must never mask a successful write.
if (Test-Path -LiteralPath $Out) {
  $kb = [math]::Round((Get-Item -LiteralPath $Out).Length / 1KB)
  W "wrote $Out ($kb KB)"
} else {
  W "WARNING: dump not found at $Out after write - check path/permissions"
}
W "next (off-host, Linux): k1rby offline `"$Out`" -o <CLIENT>-AD-Assessment.xlsx"
