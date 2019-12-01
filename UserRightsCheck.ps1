function writelog([string]$result, [string]$logfile) {
    try {
        $objlogfile = new-object system.io.streamwriter("$LogFilePath\$logfile", [System.IO.FileMode]::Append)
        $objlogfile.writeline("$((Get-Date).ToString()) : $result")
        write-host (Get-Date).ToString() " : $result"  -foregroundcolor yellow
        $objlogfile.close()
    } catch [Exception] {
        Write-Host $result -foregroundcolor red
        $error.clear()
   }
} 

$ScriptName = $MyInvocation.MyCommand.Name
$log = "UserRightsChecks.log"

writelog "================================" $log
writelog "$ScriptName Script Started" $log
writelog "--------------------------------" $log



# Fail script if we can't find SecEdit.exe
$SecEdit = Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) "SecEdit.exe"
if ( -not (Test-Path $SecEdit) ) {
  Write-Error "File not found - '$SecEdit'" -Category ObjectNotFound
  exit
}

# LookupPrivilegeDisplayName Win32 API doesn't resolve logon right display names, so use this hashtable
$UserLogonRights = @{
"SeNetworkLogonRight"="Access this computer from the network"
"SeTrustedCredManAccessPrivilege"="Access Credential Manager as a trusted caller"
"SeTcbPrivilege"="Act as part of the operating system"
"SeMachineAccountPrivilege"="Add workstations to domain"
"SeIncreaseQuotaPrivilege"="Adjust memory quotas for a process"
"SeInteractiveLogonRight"="Allow log on locally"
"SeRemoteInteractiveLogonRight"="Allow log on through Terminal Services"
"SeBackupPrivilege"="Back up files and directories"
"SeChangeNotifyPrivilege"="Bypass traverse checking"
"SeSystemtimePrivilege"="Change the system time"
"SeTimeZonePrivilege"="Change the time zone"
"SeCreatePagefilePrivilege"="Create a pagefile"
"SeCreateTokenPrivilege"="Create a token object"
"SeCreateGlobalPrivilege"="Create global objects"
"SeCreatePermanentPrivilege"="Create permanent shared objects"
"SeCreateSymbolicLinkPrivilege"="Create symbolic links"
"SeDebugPrivilege"="Debug programs"
"SeDenyNetworkLogonRight"="Deny access to this computer from the network"
"SeDenyBatchLogonRight"="Deny access to this computer from the network"
"SeDenyServiceLogonRight"="Deny log on as a service"
"SeDenyInteractiveLogonRight"="Deny log on locally"
"SeDenyRemoteInteractiveLogonRight"="Deny log on through Terminal Services"
"SeEnableDelegationPrivilege"="Enable computer and user accounts to be trusted for delegation"
"SeRemoteShutdownPrivilege"="Force shutdown from a remote system"
"SeAuditPrivilege"="Generate security audits"
"SeImpersonatePrivilege"="Impersonate a client after authentication"
"SeIncreaseWorkingSetPrivilege"="Increase a process working set"
"SeIncreaseBasePriorityPrivilege"="Increase scheduling priority"
"SeLoadDriverPrivilege"="Load and unload device drivers"
"SeLockMemoryPrivilege"="Lock pages in memory"
"SeBatchLogonRight"="Log on as a batch job"
"SeServiceLogonRight"="Log on as a service"
"SeSecurityPrivilege"="Manage auditing and security log"
"SeRelabelPrivilege"="Modify an object label"
"SeSystemEnvironmentPrivilege"="Modify firmware environment values"
"SeManageVolumePrivilege"="Perform volume maintenance tasks"
"SeProfileSingleProcessPrivilege"="Profile single process"
"SeSystemProfilePrivilege"="Profile system performance"
"SeUndockPrivilege"="Remove computer from docking station"
"SeAssignPrimaryTokenPrivilege"="Replace a process level token"
"SeRestorePrivilege"="Restore files and directories"
"SeShutdownPrivilege"="Shut down the system"
"SeSyncAgentPrivilege"="Synchronize directory service data"
"SeTakeOwnershipPrivilege"="Take ownership of files or other objects"

}

# Create type to invoke LookupPrivilegeDisplayName Win32 API
$Win32APISignature = @'
[DllImport("advapi32.dll", SetLastError=true)]
public static extern bool LookupPrivilegeDisplayName(
  string systemName,
  string privilegeName,
  System.Text.StringBuilder displayName,
  ref uint cbDisplayName,
  out uint languageId
);
'@
$AdvApi32 = Add-Type advapi32 $Win32APISignature -Namespace LookupPrivilegeDisplayName -PassThru

# Use LookupPrivilegeDisplayName Win32 API to get display name of privilege
# (except for user logon rights)
function Get-PrivilegeDisplayName {
  param(
    [String] $name
  )
  $displayNameSB = New-Object System.Text.StringBuilder 1024
  $languageId = 0
  $ok = $AdvApi32::LookupPrivilegeDisplayName($null, $name, $displayNameSB, [Ref] $displayNameSB.Capacity, [Ref] $languageId)
  if ( $ok ) {
    $displayNameSB.ToString()
  }
  else {
    # Doesn't lookup logon rights, so use hashtable for that
    if ( $UserLogonRights[$name] ) {
      $UserLogonRights[$name]
    }
    else {
      $name
    }
  }
}

# Outputs list of hashtables as a PSObject
function Out-Object {
  param(
    [System.Collections.Hashtable[]] $hashData
  )
  $order = @()
  $result = @{}
  $hashData | ForEach-Object {
    $order += ($_.Keys -as [Array])[0]
    $result += $_
  }
  New-Object PSObject -Property $result | Select-Object $order
}

# Translates a SID in the form *S-1-5-... to its account name;
function Get-AccountName {
  param(
    [String] $principal
  )
  if ( $principal[0] -eq "*" ) {
    $sid = New-Object System.Security.Principal.SecurityIdentifier($principal.Substring(1))
    $sid.Translate([Security.Principal.NTAccount])
  }
  else {
    $principal
  }
}

function TestRights($right,$SIDaccount,$FriendlyAccountName,$action){

    $TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    $LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    $StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename

$Result = @()
$Trimright = $right -replace '^.|.$', ''

If ((Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Where-Object {$_ -ilike $right}) -eq $null) {

    If($action -eq "Add"){
            
            writelog "User ($SIDaccount/$FriendlyAccountName) needs to be added to necessary security group ($Trimright) as it is currently a breach of guidelines" $log            
            
            writelog "ntrights -u $FriendlyAccountName +r $Trimright" $log
            ntrights -u $FriendlyAccountName +r $Trimright
                If($LASTEXITCODE -eq 0){
                    writelog "Successfully added $SIDaccount ($FriendlyAccountName) to $Trimright" $log
                }
                else{
                    writelog "ERROR in adding $SIDaccount ($FriendlyAccountName) to $Trimright" $log
                    writelog "$StdOut" $log
                }
        }
        elseif($action -eq "Remove"){
            writelog "User ($SIDaccount/$FriendlyAccountName) needs to be removed from necessary security group ($Trimright) as it is currently a breach of guidelines" $log
            ntrights -u $FriendlyAccountName -r $Trimright
                If($LASTEXITCODE -eq 0){
                    writelog "Successfully removed $SIDaccount ($FriendlyAccountName) from $Trimright" $log
                }
                else{
                    writelog "ERROR in removing $SIDaccount ($FriendlyAccountName) from $Trimright" $log
                    writelog "$StdOut" $log
                }
        }


}


elseif (((Select-String '^(Se\S+) = (\S+)' $TemplateFilename | Where-Object {$_ -ilike $right}).Line).Contains(("$SIDaccount"))) {
        
        writelog "Account $SIDaccount ($FriendlyAccountName) is part of $Trimright" $log 
        $Result = $true
        }        
        else{        
        writelog "Account $SIDaccount ($FriendlyAccountName) is not part of $Trimright" $log
        $Result = $false
        }

        If(($action -eq "Add") -and ($Result -eq $false)){
            
            writelog "User needs ($SIDaccount/$FriendlyAccountName) to be added to necessary security group ($Trimright) as it is currently a breach of guidelines" $log            
            
            writelog "ntrights -u $FriendlyAccountName +r $Trimright" $log
            ntrights -u $FriendlyAccountName +r $Trimright
                If($LASTEXITCODE -eq 0){
                    writelog "Successfully added $SIDaccount ($FriendlyAccountName) to $Trimright" $log
                }
                else{
                    writelog "ERROR in adding $SIDaccount ($FriendlyAccountName) to $Trimright" $log
                    writelog "$StdOut" $log
                }
        }
        elseif(($action -eq "Remove") -and ($Result -eq $true)){
            writelog "User ($SIDaccount/$FriendlyAccountName) needs to be removed from necessary security group ($Trimright) as it is currently a breach of guidelines" $log
            ntrights -u $FriendlyAccountName -r $Trimright
                If($LASTEXITCODE -eq 0){
                    writelog "Successfully removed $SIDaccount ($FriendlyAccountName) from $Trimright" $log
                }
                else{
                    writelog "ERROR in removing $SIDaccount ($FriendlyAccountName) from $Trimright" $log
                    writelog "$StdOut" $log
                }
        }
 }  

    $TemplateFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    $LogFilename = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
    $StdOut = & $SecEdit /export /cfg $TemplateFilename /areas USER_RIGHTS /log $LogFilename

     $date = Get-Date -format HH.mm.ss.dd.MM.yyyy
    (Select-String '^(Se\S+) = (\S+)' $TemplateFilename).Line > $LogFilePath\UserRightsBackup$($date).txt
    writelog "Exported existing security rights to $LogFilePath\CompLogs" $log

if ( $LASTEXITCODE -eq 0 ) {
    
    TestRights -right '*SeInteractiveLogonRight*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeNetworkLogonRight*' -SIDaccount '*S-1-5-11' -action "Add" -FriendlyAccountName 'NT AUTHORITY\Authenticated Users'
    TestRights -right '*SeNetworkLogonRight*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeIncreaseQuotaPrivilege*' -SIDaccount '*S-1-5-19' -action "Add" -FriendlyAccountName "NT AUTHORITY\LOCAL SERVICE"
    TestRights -right '*SeIncreaseQuotaPrivilege*' -SIDaccount '*S-1-5-20' -action "Add" -FriendlyAccountName "NT AUTHORITY\NETWORK SERVICE"
    TestRights -right '*SeIncreaseQuotaPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeInteractiveLogonRight*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeDenyNetworkLogonRight*' -SIDaccount '*S-1-5-32-546' -action "Add" -FriendlyAccountName "BUILTIN\Guests"
    TestRights -right '*SeDenyNetworkLogonRight*' -SIDaccount '*S-1-5-7' -action "Add" -FriendlyAccountName "NT AUTHORITY\ANONYMOUS LOGON"
    TestRights -right '*SeRemoteInteractiveLogonRight*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeRemoteInteractiveLogonRight*' -SIDaccount '*S-1-5-32-555' -action "Add" -FriendlyAccountName "BUILTIN\Remote Desktop Users"
    TestRights -right '*SeBackupPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeBackupPrivilege*' -SIDaccount '*S-1-5-32-551' -action "Add" -FriendlyAccountName "BUILTIN\Backup Operators"
    TestRights -right '*SeChangeNotifyPrivilege*' -SIDaccount '*S-1-5-32-551' -action "Add" -FriendlyAccountName "BUILTIN\Backup Operators"
    TestRights -right '*SeChangeNotifyPrivilege*' -SIDaccount '*S-1-5-19' -action "Add" -FriendlyAccountName "NT AUTHORITY\LOCAL SERVICE"
    TestRights -right '*SeChangeNotifyPrivilege*' -SIDaccount '*S-1-5-20' -action "Add" -FriendlyAccountName "NT AUTHORITY\NETWORK SERVICE"
    TestRights -right '*SeChangeNotifyPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeChangeNotifyPrivilege*' -SIDaccount '*S-1-5-11' -action "Add" -FriendlyAccountName "NT AUTHORITY\Authenticated Users"
    TestRights -right '*SeTimeZonePrivilege*' -SIDaccount '*S-1-5-19' -action "Remove" -FriendlyAccountName "NT AUTHORITY\LOCAL SERVICE"
    TestRights -right '*SeTimeZonePrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeCreatePagefilePrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeCreateGlobalPrivilege*' -SIDaccount '*S-1-5-19' -action "Add" -FriendlyAccountName "NT AUTHORITY\LOCAL SERVICE"
    TestRights -right '*SeCreateGlobalPrivilege*' -SIDaccount '*S-1-5-20' -action "Add" -FriendlyAccountName "NT AUTHORITY\NETWORK SERVICE"
    TestRights -right '*SeCreateGlobalPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeCreateGlobalPrivilege*' -SIDaccount '*S-1-5-6' -action "Add" -FriendlyAccountName "NT AUTHORITY\SERVICE"
    TestRights -right '*SeCreateSymbolicLinkPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeDebugPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeDenyBatchLogonRight*' -SIDaccount '*S-1-5-32-546' -action "Add" -FriendlyAccountName "BUILTIN\Guests"
    TestRights -right '*SeDenyInteractiveLogonRight*' -SIDaccount '*S-1-5-32-546' -action "Add" -FriendlyAccountName "BUILTIN\Guests"
    TestRights -right '*SeDenyRemoteInteractiveLogonRight*' -SIDaccount '*S-1-5-32-546' -action "Add" -FriendlyAccountName "BUILTIN\Guests"
    TestRights -right '*SeRemoteShutdownPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeAuditPrivilege*' -SIDaccount '*S-1-5-19' -action "Add" -FriendlyAccountName "NT AUTHORITY\LOCAL SERVICE"
    TestRights -right '*SeAuditPrivilege*' -SIDaccount '*S-1-5-20' -action "Add" -FriendlyAccountName "NT AUTHORITY\NETWORK SERVICE"
    TestRights -right '*SeImpersonatePrivilege*' -SIDaccount '*S-1-5-19' -action "Add" -FriendlyAccountName "NT AUTHORITY\LOCAL SERVICE"
    TestRights -right '*SeImpersonatePrivilege*' -SIDaccount '*S-1-5-20' -action "Add" -FriendlyAccountName "NT AUTHORITY\NETWORK SERVICE"
    TestRights -right '*SeImpersonatePrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeImpersonatePrivilege*' -SIDaccount '*S-1-5-6' -action "Add" -FriendlyAccountName "NT AUTHORITY\SERVICE"
    TestRights -right '*SeIncreaseWorkingSetPrivilege*' -SIDaccount '*S-1-5-32-545' -action "Add" -FriendlyAccountName "BUILTIN\Users"
    TestRights -right '*SeIncreaseBasePriorityPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeLoadDriverPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeBatchLogonRight*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeBatchLogonRight*' -SIDaccount '*S-1-5-32-551' -action "Remove" -FriendlyAccountName "BUILTIN\Backup Operators"
    TestRights -right '*SeBatchLogonRight*' -SIDaccount '*S-1-5-32-559' -action "Add" -FriendlyAccountName "BUILTIN\Performance Log Users"
    TestRights -right '*SeServiceLogonRight*' -SIDaccount '*S-1-5-80-0' -action "Add" -FriendlyAccountName "NT SERVICE\ALL SERVICES"
    TestRights -right '*SeSecurityPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeSystemEnvironmentPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeManageVolumePrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeProfileSingleProcessPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeUndockPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeProfileSingleProcessPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeShutdownPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeTakeOwnershipPrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeSystemProfilePrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeSystemProfilePrivilege*' -SIDaccount '*S-1-5-80-3139157870-2983391045-3678747466-658725712-1809340420' -action "Add" -FriendlyAccountName "NT SERVICE\WdiServiceHost"
    TestRights -right '*SeAssignPrimaryTokenPrivilege*' -SIDaccount '*S-1-5-19' -action "Add" -FriendlyAccountName "NT AUTHORITY\LOCAL SERVICE"
    TestRights -right '*SeAssignPrimaryTokenPrivilege*' -SIDaccount '*S-1-5-20' -action "Add" -FriendlyAccountName "NT AUTHORITY\NETWORK SERVICE"
    TestRights -right '*SeRestorePrivilege*' -SIDaccount '*S-1-5-32-544' -action "Add" -FriendlyAccountName "BUILTIN\Administrators"
    TestRights -right '*SeRestorePrivilege*' -SIDaccount '*S-1-5-32-551' -action "Add" -FriendlyAccountName "BUILTIN\Backup Operators"
    
}
else {
  $OFS = ""
  Write-Error "$StdOut"
}

writelog "$ScriptName Script ended" $log
writelog "==============================" $log

