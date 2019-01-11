    $osqueryd_path = ".\osqueryd"
    $acl = Get-Item $osqueryd_path |get-acl
    $acl.SetAccessRuleProtection($true,$true)
    $acl |Set-Acl

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

    sc.exe create hubble_osqueryd binpath= '\"C:\Program Files (x86)\Hubble\osqueryd\osqueryd.exe\" --flagfile=\"C:\Program Files (x86)\Hubble\var\cache\files\base\osqueryd\osquery.flags\" --config_path=\"C:\Program Files (x86)\Hubble\var\cache\files\base\osqueryd\osquery.conf\"' displayname= "hubble_osqueryd"
    sc.exe config hubble_osqueryd depend= Hubble
