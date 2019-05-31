    $hubble_path = $args[0]
    $osqueryd_path = $hubble_path + "\osqueryd\"
    $osqueryd_conffile_path = $hubble_path + "\var\cache\files\base\hubblestack_nebula_v2\osquery.conf"
    $osqueryd_flagfile_path = $hubble_path + "\var\cache\files\base\hubblestack_nebula_v2\osquery.flags"
    $osqueryd_logfile_path = $hubble_path + "\var\log\hubble_osquery"
    $osqueryd_backuplog_path = $osqueryd_logfile_path + "\backuplogs"

    $acl = Get-Item $osqueryd_path |get-acl
    $acl.SetAccessRuleProtection($true,$true)
    $acl |Set-Acl
    $binpath = "\" + '"' + $osqueryd_path + "osqueryd.exe" + "\" + '"' 	+ " --flagfile=\" + '"' + $osqueryd_flagfile_path + "\" + '"' + " --config_path=\" + '"' + $osqueryd_conffile_path + "\" + '"' + " --logger_path=\" + '"' + $osqueryd_logfile_path + "\" + '"'
    $osqueryd_service_name = "hubble_osqueryd"

    $group = "NT SERVICE\TrustedInstaller"
    $acl = Get-Acl $osqueryd_path
    $inherit =[system.security.accesscontrol.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propagation =[system.security.accesscontrol.PropagationFlags]"None"
    $accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule($group,"FullControl", $inherit, $Propagation ,,,"Allow")
    $acl.RemoveAccessRuleAll($accessrule)
    set-acl -aclobject $acl $osqueryd_path

    $group = "ALL APPLICATION PACKAGES"
    $acl = Get-Acl $osqueryd_path
    $inherit =[system.security.accesscontrol.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propagation =[system.security.accesscontrol.PropagationFlags]"None"
    $accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule($group,"FullControl", $inherit, $Propagation ,,,"Allow")
    $acl.RemoveAccessRuleAll($accessrule)
    set-acl -aclobject $acl $osqueryd_path

    $group = "ALL APPLICATION PACKAGES"
    $acl = Get-Acl $osqueryd_path
    $inherit =[system.security.accesscontrol.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propagation =[system.security.accesscontrol.PropagationFlags]"None"
    $accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule($group,"Write", $inherit, $Propagation ,,,"Deny")
    $acl.AddAccessRule($accessrule)
    set-acl -aclobject $acl $osqueryd_path

    $group = "ALL RESTRICTED APPLICATION PACKAGES"
    $acl = Get-Acl $osqueryd_path
    $inherit =[system.security.accesscontrol.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propagation =[system.security.accesscontrol.PropagationFlags]"None"
    $accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule($group,"FullControl", $inherit, $Propagation ,,,"Allow")
    $acl.RemoveAccessRuleAll($accessrule)
    set-acl -aclobject $acl $osqueryd_path

    $group = "CREATOR OWNER"
    $acl = Get-Acl $osqueryd_path
    $inherit =[system.security.accesscontrol.InheritanceFlags]"ContainerInherit,ObjectInherit"
    $propagation =[system.security.accesscontrol.PropagationFlags]"None"
    $accessrule = New-Object System.Security.AccessControl.FileSystemAccessRule($group,"FullControl", $inherit, $Propagation ,,,"Allow")
    $acl.RemoveAccessRuleAll($accessrule)
    set-acl -aclobject $acl $osqueryd_path

    if(!(Test-Path -Path $osqueryd_backuplog_path )){
        New-Item -Path $osqueryd_backuplog_path -ItemType Directory
    }

    sc.exe create $osqueryd_service_name binpath=$binpath  displayname=$osqueryd_service_name
    sc.exe config $osqueryd_service_name depend= Hubble
