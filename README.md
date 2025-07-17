[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
# Invoke-BadSuccessorCheck

A PowerShell tool designed to detect Windows Server 2025 domain controllers and identify organizational units (OUs) where the current user has CreateChild permissions.

## Overview

This script performs two critical security checks in an Active Directory environment:

1. Identifies any Windows Server 2025 domain controllers in the domain
2. Checks all organizational units (OUs) to determine if the current user has CreateChild permissions

The combination of these checks is particularly valuable for security professionals who wish to check for the BadSuccessor dMSA vulnerability or administrators auditing domain permissions.


## Prerequisites

- Windows PowerShell 5.1 or later
- Domain-joined machine
- User account with at least read access to AD objects
- Active Directory module recommended but not required (falls back to ADSI)

## Usage

Simply run the script from a PowerShell prompt on a domain-joined machine:

```powershell
.\Invoke-BadSuccessorCheck.ps1
```

No parameters are required as the script automatically detects the current domain and user context.

## Example Output

```
===== Checking DC Versions and OU CreateChild permissions =====
Domain: CONTOSO.LOCAL
Domain DN: DC=CONTOSO,DC=LOCAL

Current user: CONTOSO\jsmith
Finding domain controllers and OS versions...
Found 2 domain controllers

==== DOMAIN CONTROLLERS =====
- DC01: Windows Server 2019 Standard
- DC02: Windows Server 2025 Standard
  
Testing CreateChild permissions on each OU...
[33%] Testing OU=Domain Controllers,DC=CONTOSO,DC=LOCAL...
  - No CreateChild permission
[67%] Testing OU=Marketing,DC=CONTOSO,DC=LOCAL...
  - CREATE PERMISSION FOUND!
[100%] Testing OU=IT,DC=CONTOSO,DC=LOCAL...
  - No CreateChild permission

===== FINAL RESULTS =====
Domain Controller Summary:
Found 1 Windows Server 2025 domain controllers out of 2 total DCs

CreateChild Permissions Summary:
The current user HAS CreateChild permissions on 1 OUs:
- Marketing (OU=Marketing,DC=CONTOSO,DC=LOCAL)
```

## How It Works

1. The script first identifies the current domain and user context
2. It searches for domain controllers using either Active Directory PowerShell module or direct ADSI queries
3. For each domain controller, it retrieves and displays the operating system version
4. The script then enumerates all OUs in the domain
5. For each OU, it checks if the current user (or their group memberships) has CreateChild permissions
6. Finally, it presents a summary of findings, highlighting any Windows Server 2025 DCs and OUs where the user has CreateChild permissions
