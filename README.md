# AutoSignARM
A PowerShell script that automates the process of JWT assertion.
The script supports both AccessTokens and passwords.

## Execution Options

Execute with tokens:

```PowerShell
  Invoke-AutoSignARM -TenantId <TenantID> -TargetID <AppIDofTargetSP> -keyVault <keyVaultName> -CertName <CertificateName> -Username <UPNofTheAbuser> -UseTokens
```

Execute with password:

```PowerShell
  Invoke-AutoSignARM -TenantId <TenantID> -TargetID <AppIDofTargetSP> -keyVault <keyVaultName> -CertName <CertificateName> -Username <UPNofTheAbuser> -password <passwordOfAbuser>
```

Execute with tokens and permissions verification:

```PowerShell
  Invoke-AutoSignARM -TenantId <TenantID> -TargetID <AppIDofTargetSP> -keyVault <keyVaultName> -CertName <CertificateName> -Username <UPNofTheAbuser> -IsSigningPermissions -UseTokens
```
