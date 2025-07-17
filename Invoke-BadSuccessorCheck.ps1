# Import necessary module if available
if (Get-Module -ListAvailable -Name ActiveDirectory) {
    Import-Module ActiveDirectory -ErrorAction SilentlyContinue
}

# Get domain information from environment
$domainName = $env:USERDNSDOMAIN
$domainDN = "DC=$($domainName.Replace('.', ',DC='))"

Write-Host "===== Checking DC Versions and OU CreateChild permissions =====" -ForegroundColor Cyan
Write-Host "Domain: $domainName" -ForegroundColor Green
Write-Host "Domain DN: $domainDN" -ForegroundColor Green
Write-Host ""

# Get current user information
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$userName = $currentUser.Name
Write-Host "Current user: $userName" -ForegroundColor Green

# Function to get domain controllers and their OS versions
function Get-DomainControllers {
    Write-Host "Finding domain controllers and OS versions..." -ForegroundColor Yellow
    $dcs = @()
    
    try {
        # Try using built-in PowerShell commands first
        if (Get-Command Get-ADDomainController -ErrorAction SilentlyContinue) {
            $adDCs = Get-ADDomainController -Filter * -ErrorAction SilentlyContinue
            
            foreach ($dc in $adDCs) {
                $server = $dc.Name
                $os = "Unknown"
                
                try {
                    $computerObj = Get-ADComputer -Identity $server -Properties OperatingSystem -ErrorAction SilentlyContinue
                    $os = $computerObj.OperatingSystem
                }
                catch {
                    # Failed to get OS info
                }
                
                $dcs += [PSCustomObject]@{
                    Name = $server
                    OperatingSystem = $os
                    IsWindows2025 = $os -like "*2025*"
                }
            }
        }
        else {
            # Use ADSI to find DCs
            $searcher = New-Object System.DirectoryServices.DirectorySearcher
            $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$domainDN")
            $searcher.Filter = "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=8192))"
            $searcher.PropertiesToLoad.Add("name") | Out-Null
            $searcher.PropertiesToLoad.Add("operatingSystem") | Out-Null
            
            $results = $searcher.FindAll()
            
            foreach ($result in $results) {
                $server = $result.Properties["name"][0]
                $os = "Unknown"
                
                if ($result.Properties.Contains("operatingsystem")) {
                    $os = $result.Properties["operatingsystem"][0]
                }
                
                $dcs += [PSCustomObject]@{
                    Name = $server
                    OperatingSystem = $os
                    IsWindows2025 = $os -like "*2025*"
                }
            }
        }
        
        Write-Host "Found $($dcs.Count) domain controllers" -ForegroundColor Green
        
        # Display DC information
        Write-Host "`n==== DOMAIN CONTROLLERS =====" -ForegroundColor Cyan
        foreach ($dc in $dcs) {
            $color = "White"
            if ($dc.IsWindows2025) {
                $color = "Green"
            }
            
            Write-Host "- $($dc.Name): $($dc.OperatingSystem)" -ForegroundColor $color
        }
        Write-Host ""
    }
    catch {
        Write-Host "Error finding domain controllers: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $dcs
}

# Get domain controller information
$domainControllers = Get-DomainControllers

# Function to find OUs in the domain
function Find-DomainOUs {
    param ($DomainDN)
    
    Write-Host "Searching for OUs in domain: $DomainDN" -ForegroundColor Yellow
    $ous = @()
    
    try {
        # Use ADSI search
        $searcher = New-Object System.DirectoryServices.DirectorySearcher
        $searcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainDN")
        $searcher.Filter = "(objectClass=organizationalUnit)"
        $searcher.SearchScope = "Subtree"
        
        $results = $searcher.FindAll()
        
        foreach ($result in $results) {
            $ou = New-Object PSObject -Property @{
                Name = $result.Properties["name"][0]
                DistinguishedName = $result.Properties["distinguishedname"][0]
            }
            $ous += $ou
        }
        
        Write-Host "Found $($ous.Count) OUs" -ForegroundColor Green
    }
    catch {
        Write-Host "Error searching for OUs: $($_.Exception.Message)" -ForegroundColor Red
    }
    
    return $ous
}

# More accurate function to check CreateChild permissions using ADSI and security descriptors
function Test-CreatePermission {
    param ($OuDN)
    
    try {
        # Get current user SID
        $currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
        $userSID = $currentUser.User.Value
        $userGroups = $currentUser.Groups | ForEach-Object { $_.Value }
        
        # Connect to the OU
        $ou = [ADSI]"LDAP://$OuDN"
        if ($null -eq $ou.distinguishedName) {
            Write-Host "  - Could not connect to OU" -ForegroundColor Yellow
            return $false
        }
        
        # Get security descriptor
        $securityDescriptor = $ou.psbase.ObjectSecurity
        if ($null -eq $securityDescriptor) {
            Write-Host "  - Unable to access security descriptor" -ForegroundColor Yellow
            return $false
        }
        
        # Define the CreateChild right value
        # CreateChild right is 0x1 in Active Directory
        $RIGHT_DS_CREATE_CHILD = 0x1
        
        # Get the access rules
        $accessRules = $securityDescriptor.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])
        
        # Check if current user or any of their groups has CreateChild right
        $hasPermission = $false
        foreach ($rule in $accessRules) {
            # Only care about Allow rules
            if ($rule.AccessControlType -ne "Allow") {
                continue
            }
            
            # Check if this rule applies to the current user or their groups
            $ruleSID = $rule.IdentityReference.Value
            if (($ruleSID -eq $userSID) -or ($userGroups -contains $ruleSID)) {
                # Check if the rule grants CreateChild right
                if (($rule.ActiveDirectoryRights -band $RIGHT_DS_CREATE_CHILD) -eq $RIGHT_DS_CREATE_CHILD) {
                    $hasPermission = $true
                    break
                }
            }
        }
        
        # Also check special well-known SIDs like Everyone and Authenticated Users
        $wellKnownSIDs = @("S-1-1-0", "S-1-5-11") # Everyone and Authenticated Users
        foreach ($rule in $accessRules) {
            if ($rule.AccessControlType -ne "Allow") {
                continue
            }
            
            $ruleSID = $rule.IdentityReference.Value
            if ($wellKnownSIDs -contains $ruleSID) {
                if (($rule.ActiveDirectoryRights -band $RIGHT_DS_CREATE_CHILD) -eq $RIGHT_DS_CREATE_CHILD) {
                    $hasPermission = $true
                    break
                }
            }
        }
        
        return $hasPermission
    }
    catch {
        Write-Host "  - Error checking permissions: $($_.Exception.Message)" -ForegroundColor Yellow
        return $false
    }
}

# Find all OUs in the domain
$allOUs = Find-DomainOUs -DomainDN $domainDN

if ($allOUs.Count -eq 0) {
    Write-Host "No OUs found. Exiting." -ForegroundColor Red
    exit
}

# Test each OU for CreateChild permissions
Write-Host "`nTesting CreateChild permissions on each OU..." -ForegroundColor Yellow
$permittedOUs = @()

$total = $allOUs.Count
$current = 0

foreach ($ou in $allOUs) {
    $current++
    $percent = [int](($current / $total) * 100)
    
    Write-Progress -Activity "Testing OU Permissions" -Status "$percent% Complete" -PercentComplete $percent
    Write-Host "[$percent%] Testing $($ou.DistinguishedName)..." -ForegroundColor Gray
    
    $hasPermission = Test-CreatePermission -OuDN $ou.DistinguishedName
    
    if ($hasPermission) {
        Write-Host "  - CREATE PERMISSION FOUND!" -ForegroundColor Green
        $permittedOUs += $ou
    }
    else {
        Write-Host "  - No CreateChild permission" -ForegroundColor Yellow
    }
}

Write-Progress -Activity "Testing OU Permissions" -Completed

# Complete progress bar
Write-Progress -Activity "Testing OU Permissions" -Completed

# Output final results
Write-Host "`n===== FINAL RESULTS =====" -ForegroundColor Cyan

# DC summary
Write-Host "Domain Controller Summary:" -ForegroundColor Magenta
if ($domainControllers.Count -gt 0) {
    $windows2025Count = ($domainControllers | Where-Object {$_.IsWindows2025}).Count
    if ($windows2025Count -gt 0) {
        Write-Host "Found $windows2025Count Windows Server 2025 domain controllers out of $($domainControllers.Count) total DCs" -ForegroundColor Green
    }
    else {
        Write-Host "No Windows Server 2025 domain controllers found" -ForegroundColor Yellow
    }
}
else {
    Write-Host "No domain controllers information available" -ForegroundColor Yellow
}

# OU Permissions summary
Write-Host "`nCreateChild Permissions Summary:" -ForegroundColor Magenta
if ($permittedOUs.Count -eq 0) {
    Write-Host "The current user DOES NOT have CreateChild permissions on any OUs" -ForegroundColor Yellow
}
else {
    Write-Host "The current user HAS CreateChild permissions on $($permittedOUs.Count) OUs:" -ForegroundColor Green
    foreach ($ou in $permittedOUs) {
        Write-Host "- $($ou.Name) ($($ou.DistinguishedName))" -ForegroundColor Green
    }
}
