$hubble_path = $args[0]
$hubble_conf_path = $hubble_path + "\etc\hubble\"
Write-Host $hubble_conf_path
$acl = Get-Acl $hubble_conf_path

$acl.SetAccessRuleProtection($true, $false)
foreach ($access in $acl.Access) {
  $acl.RemoveAccessRule($access)
}
Set-Acl $hubble_conf_path $acl
Write-Host "Succesfully removed all permissions from file"

$acl = Get-Acl $hubble_conf_path
$inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
$propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
$permType = [System.Security.AccessControl.AccessControlType]::Allow
$grantedPerm = 'FullControl'

$systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
$systemUser = $systemSid.Translate([System.Security.Principal.NTAccount])
Write-Host $systemUser

$adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
$adminsGroup = $adminsSid.Translate([System.Security.Principal.NTAccount])
Write-Host $adminsGroup

$permGroups = @($systemUser, $adminsGroup)
foreach ($accnt in $permGroups) {
  $permission = $accnt.Value, $grantedPerm, $inheritanceFlag, $propagationFlag, $permType
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  Write-Host $accessRule
  $acl.SetAccessRule($accessRule)
    }
$acl.SetOwner($adminsGroup)
Set-Acl $hubble_conf_path $acl