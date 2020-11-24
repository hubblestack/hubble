    $hubble_path = $args[0]
    $osqueryd_path = $hubble_path + "\osqueryd\"
    $osqueryd_conffile_path = $hubble_path + "\var\cache\files\base\hubblestack_nebula_v2\osquery.conf"
    $osqueryd_flagfile_path = $hubble_path + "\var\cache\files\base\hubblestack_nebula_v2\osquery.flags"
    $osqueryd_logfile_path = $hubble_path + "\var\log\hubble_osquery"
    $osqueryd_backuplog_path = $osqueryd_logfile_path + "\backuplogs"
    $osqueryd_service_name = "hubble_osqueryd"
    $binpath = "\" + '"' + $osqueryd_path + "osqueryd.exe" + "\" + '"'  + " --flagfile=\" + '"' + $osqueryd_flagfile_path + "\" + '"' + " --config_path=\" + '"' + $osqueryd_conffile_path + "\" + '"' + " --logger_path=\" + '"' + $osqueryd_logfile_path + "\" + '"'
    $target = $osqueryd_path
    $acl = Get-Acl $target

    # First, to ensure success, we remove the entirety of the ACL
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($access in $acl.Access) {
      $acl.RemoveAccessRule($access)
    }
    Set-Acl $target $acl

    $acl = Get-Acl $target
    $inheritanceFlag = [System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    $propagationFlag = [System.Security.AccessControl.PropagationFlags]::None
    $permType = [System.Security.AccessControl.AccessControlType]::Allow

    # "Safe" permissions in osquery entail the containing folder and binary both
    # are owned by the Administrators group, as well as no account has Write
    # permissions except for the Administrators group and SYSTEM account
    $systemSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-18')
    $systemUser = $systemSid.Translate([System.Security.Principal.NTAccount])

    $adminsSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')
    $adminsGroup = $adminsSid.Translate([System.Security.Principal.NTAccount])

    $usersSid = New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-545')
    $usersGroup = $usersSid.Translate([System.Security.Principal.NTAccount])

    $permGroups = @($systemUser, $adminsGroup, $usersGroup)
    foreach ($accnt in $permGroups) {
      $grantedPerm = ''
      if ($accnt -eq $usersGroup) {
        $grantedPerm = 'ReadAndExecute'
      } else {
        $grantedPerm = 'FullControl'
      }
      $permission = $accnt.Value, $grantedPerm, $inheritanceFlag, $propagationFlag, $permType
      $accessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $permission
      $acl.SetAccessRule($accessRule)
    }
    $acl.SetOwner($adminsGroup)
    Set-Acl $target $acl

    # Finally set the Administrators group as the owner for all items
    $items = Get-ChildItem -Recurse -Path $target
    foreach ($item in $items) {
      $acl = Get-Acl -Path $item.FullName
      $acl.SetOwner($adminsGroup)
      Set-Acl $item.FullName $acl
    }
  
  if(!(Test-Path -Path $osqueryd_backuplog_path )){
        New-Item -Path $osqueryd_backuplog_path -ItemType Directory
    }

    sc.exe create $osqueryd_service_name binpath=$binpath  displayname=$osqueryd_service_name
    sc.exe config $osqueryd_service_name depend= Hubble
