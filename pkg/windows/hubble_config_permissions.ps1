$hubble_path = $args[0]
$hubble_conf_path = $hubble_path + "\etc\hubble"
$hubble_conf_file_path = $hubble_conf_path + "\hubble.conf"
Write-Host $hubble_conf_path
$acl = Get-Acl $hubble_conf_path

$acl.SetAccessRuleProtection($true, $false)
foreach ($access in $acl.Access) {
  $acl.RemoveAccessRule($access)
}
Set-Acl $hubble_conf_path $acl
Write-Host "Successfully removed all permissions from file"

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

$items = Get-ChildItem -Recurse -Path $hubble_conf_path
foreach ($item in $items) {
  $acl = Get-Acl -Path $item.FullName
  $acl.SetOwner($adminsGroup)
  Set-Acl $item.FullName $acl
}

$acl1 = Get-Acl $hubble_conf_file_path
foreach ($accnt in $permGroups) {
  $permission = $accnt.Value, $grantedPerm, 'None', $propagationFlag, $permType
  $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
  Write-Host $accessRule
  $acl1.SetAccessRule($accessRule)
    }
$acl1.SetOwner($adminsGroup)
Set-Acl $hubble_conf_file_path $acl1