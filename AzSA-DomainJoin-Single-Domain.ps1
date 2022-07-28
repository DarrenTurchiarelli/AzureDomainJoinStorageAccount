<#
.SYNOPSIS
     Perform an Active Directory Domain Join for tagged storage accounts

.DESCRIPTION
    - Creates a computer object in Active Directory sets the properties of the storage account with domain configuration 
    - Queries all subscriptions within an Azure tenant and subsequently queries all Storage Accounts (SA) for the tag key pair value 'Domain:Connected'
    - Validates within Active Directory that the computer object exists
    - Validates the storage account to generate a new key with the name 'kerb1'
    - Creates a user identity in Active Directory using the 'kerb1' key as the identity's password
    - Set the Service Principal value of the new identity to be: cifs/<StorageAccountName>.file.core.windows.net.
    - Updates the kerb value and password for computer object every 14 days 
    - Validates the AD object and kerb values match and reset in the event of a mismatch

.NOTES
     You must apply a tag on the storage account with a name-value pair 'Domain:Connected' 

.LINK
    - https://docs.microsoft.com/en-us/azure/storage/common/storage-account-overview
    - https://docs.microsoft.com/en-us/azure/automation/overview

.EXAMPLE
   
#>

param(
    [Parameter(Mandatory = $True, Position = 1, HelpMessage = "Domain NetBIOS name - DOMAINDEV DOMAINTEST, DOMAINPROD")]
    [validateset('DOMAINDEV' , 'DOMAINTEST' , 'DOMAINPROD')]
    [string]$DomainName,

    [Parameter(Mandatory = $True, Position = 2, HelpMessage = "Azure Automation Credential Name")]
    [string]$AzCredentialname
)

# Specify your Active Directory Domain Name 
$Domain = "domainame.com" 

# Specify your Active Directory Organisational Unit, where the storage account object will reside 
$Path = "OU=Azure,OU=Cloud,DC=domainname,DC=com"

#Set you Microsoft Teams channel, that you want to send alerts to 
$NotificationUri = "INSERT-MICROSOFT-TEAMS-WEBHOOK-HERE"

# Update the PDate varaible below to however often you want to rotate the kerb key 
$PDate = [datetime]::Today.AddDays(-14)

# Output to screen
  Write-output "Script has started on Hybrid Worker: $(hostname)"

function Send-Output {
    param([string]$Message,
          [string]$WebhookUri)

    $body = @{
            text = $Message
    }

    Invoke-WebRequest -Uri $WebhookUri -UseBasicParsing -Method POST -Body ($body | ConvertTo-Json)
}

Function Start-StorageAccountDomainJoin {

    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $True, Position = 1, HelpMessage = "Storage Account Name")]
        [string]$StorageAccountName,

        [Parameter(Mandatory = $True, Position = 2, HelpMessage = "Resource Group Name")]
        [string]$ResourceGroupName,

        [Parameter(Mandatory = $True, Position = 3, HelpMessage = "Domain FQDN")]
        [string]$Domain,

        [Parameter(Mandatory = $True, Position = 4, HelpMessage = "OU Distinguised Name")]
        [string]$Path
    )

    try { 

        $StorageAccountObject = Get-AzStorageAccount -ResourceGroup $ResourceGroupName -Name $StorageAccountName
        $ServicePrincipalName = $StorageAccountObject.PrimaryEndpoints.File -replace 'https://', 'cifs/'
        $ServicePrincipalName = $ServicePrincipalName.Substring(0, $ServicePrincipalName.Length - 1);
        $SPNValue = $ServicePrincipalName

        $Keys = New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -KeyName kerb1 -Erroraction Stop
        $Kerb1key = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ListKerbKey -ErrorAction Stop | Where-Object {$_.KeyName -eq "kerb1" }
        $FileServiceAccountPwdSecureString = ConvertTo-SecureString -String $Kerb1key.Value -AsPlainText -Force

        $DomainController = Get-ADDomainController -Discover -DomainName $Domain
        $AzureStorageIdentity = New-ADComputer -SAMAccountName $StorageAccountName `
            -Path $path `
            -Name $StorageAccountName `
            -AccountPassword $FileServiceAccountPwdSecureString `
            -AllowReversiblePasswordEncryption $false `
            -Description "Computer account object for Azure Storage Account $StorageAccountName." `
            -Credential $AzCredential `
            -ServicePrincipalNames $SPNValue -Server $DomainController.Name -Enabled $True -ErrorAction Stop -PassThru


        Write-output "Computer object has been created for storage account $($StorageAccountName)"

        $AzureStorageSid = $AzureStorageIdentity.SID.Value
        $DomainInformation = Get-ADDomain -Server $DomainController.Name
        $DomainGuid = $DomainInformation.ObjectGUID.ToString()
        $DomainName = $DomainInformation.DnsRoot
        $DomainSid = $DomainInformation.DomainSid.value
        $ForestName = $DomainInformation.Forest
        $NetBiosDomainName = $DomainInformation.DnsRoot

        Write-Output "Setting AD properties on $StorageAccountName in $ResourceGroupName : `
                        EnableActiveDirectoryDomainServicesForFile=$True, ActiveDirectoryDomainName=$DomainName, `
                        ActiveDirectoryNetBiosDomainName=$NetBiosDomainName, ActiveDirectoryForestName=$($DomainInformation.Forest) `
                        ActiveDirectoryDomainGuid=$DomainGuid, ActiveDirectoryDomainSid=$DomainSid, '
                        ActiveDirectoryAzureStorageSid=$AzureStorageSid"

        Set-AzStorageAccount -ResourceGroupName $ResourceGroupName -AccountName $StorageAccountName `
            -EnableActiveDirectoryDomainServicesForFile $True -ActiveDirectoryDomainName $DomainName `
            -ActiveDirectoryNetBiosDomainName $NetBiosDomainName -ActiveDirectoryForestName $ForestName `
            -ActiveDirectoryDomainGuid $DomainGuid -ActiveDirectoryDomainSid $DomainSid `
            -ActiveDirectoryAzureStorageSid $AzureStorageSid
    }
    catch{
        Send-Output -WebHookUri $NotificationUri -Message "$((Get-Azcontext).Subscription.Name) --- $($StorageAccountName) Domain Join Failed"
        Send-Output -WebHookUri $NotificationUri -Message "$($_.Exception.Message) --- $($_.Exception.StackTrace)"
        exit;
    } 

}

    Function Update-StorageAccountDomainPwd {

       [CmdletBinding()]
         param (
            [Parameter(Mandatory = $True, Position = 1, HelpMessage = "Storage Account Name")]
            [string]$StorageAccountName,

            [Parameter(Mandatory = $True, Position = 2, HelpMessage = "Resource Group Name")]
            [string]$ResourceGroupName,

            [Parameter(Mandatory = $True, Position = 3, HelpMessage = "Domain FQDN")]
            [string]$Domain
        )

        try {

            $DomainController = Get-ADDomainController -Discover -DomainName $Domain
            $StorageAccountObject = Get-ADComputer -Identity $StorageAccountName -Server $DomainController.Name

            $Keys = New-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -Keyname keyb1 -Erroraction Stop
            $Kerb1key = Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName -Name $StorageAccountName -ListKerbKey -ErrorAction Stop | Where-Object {$_.KeyName -eq "kerb1" }
            $FileServiceAccountPwdSecureString = ConvertTo-SecureString -String $Kerb1key.Value -AsPlainText -Force

        Set-ADAccountPassword -Identity $StorageAccountObject.SAMAccountName `
            -Server $DomainController -Reset `
            -NewPassword $FileServiceAccountPwdSecureString
            -PassThru `
            -Credential $AzCredential `
            -ErrorAction Stop

        Write-Output "Computer object password reset successfully: $($StorageAccountName)"
        }
        catch {
            Send-Output -WebHookUri $NotificationUri -Message "$((Get-Azcontext).Subscription.Name) --- $(StorageAccountName) Domain Join Failed"
            Send-Output -WebHookUri $NotificationUri -Message "$($_.Exception.Message) --- $($_.Exception.StackTrace)"
            exit;
        }
    } 

    Function Test-StorageAccountKey {

        [CmdletBinding()]
          param (
             [Parameter(Mandatory = $True, Position = 1, HelpMessage = "Storage Account Name")]
             [string]$StorageAccountName,
 
             [Parameter(Mandatory = $True, Position = 2, HelpMessage = "Resource Group Name")]
             [string]$ResourceGroupName,
 
             [Parameter(Mandatory = $True, Position = 3, HelpMessage = "Domain FQDN")]
             [string]$Domain
         )

         try {

            $KeyMatches = $null
            $Kerb1key =Get-AzStorageAccountKey -ResourceGroupName $ResourceGroupName `
                -Name $StorageAccountName -ListKerbKey `
                -ErrorAction Stop | Where-Object { $_.KeyName -eq "kerb1" }

            $DomainController = Get-ADDomainController -Discover -DomainName $domain
            $StorageADObject = Get-ADComputer -Identity $StorageAccountName -Server $DomainController.Name
            $Username = $DomainController.Domain + "\" + $StorageADObject.Name


            if ((New-Object DirectoryServices.DirectoryEntry "", $Username, $Kerb1key.Value).PsBase.Name -ne $null) {
                Return $True

            }
            Else {
                Send-Output -WebhookUri $NotificationUri -Message "$((Get-Azcontext).Subscription.Name)  ---  $($StorageAccountName) has an invalid key"
                Return $false

            }
        }
        Catch {
            Send-Output -WebHookUri $NotificationUri -Message "$($_.Exception.Message) --- $($_.Exception.StackTrace)"
            exit;
        }
    }


    $AzureIdentity = Get-AutomationPSCredential -Name $AzCredentialname
    $AzAccount = $AzureIdentity.Username
    $AzPassword = $AzureIdentity.password
    $AzCredential = New-Object -TypeName System.Management.Automation.PSCredential ($AzAccount, $AzPassword)
    Connect-AzAccount -Credential $AzCredential

    $Allsubscriptions = Get-AzSubscription

    foreach ($sub in $Allsubscriptions) { 

        Set-AzContext -Subscription $sub.Id | Out-Null
        Write-Output "Script is running on subscription: $((Get-Azcontext).Subscription.Name)"
        $AllstorageaccountsinSub = Get-AzStorageAccount

        foreach ($StAccount in $AllstorageaccountsinSub) {

            if ($StAccount.Tags.Domain -eq "Connected") {

                $DomainController = Get-ADDomainController -Discover -DomainName $Domain
                $CheckstorageADObject = Get-ADComputer -Filter 'Name -like $StAccount.StorageAccountName' `
                    -Server $DomainController.Name `
                    -Properties * `
                    -ErrorAction SilentlyContinue 
                
                $StADdomain = $StAccount.AzureFilesIdentityBasedAuth.ActiveDirectoryProperties.DomainName

                if ($CheckstorageADObject -eq $null) {

                    Write-Output "Starting Domain join process for Storage Account: $($StAccount.StorageAccountName)"
                    Start-StorageAccountDomainJoin -StorageAccountName $StAccount.StorageAccountName `
                        -ResourceGroupName $StAccount.ResourceGroupName `
                        -Domain $Domain `
                        -Path $Path 
                }
                ElseIf ($CheckstorageADObject -ne $null -and $StADdomain -eq $null) { 

                        Write-Output "Storage Account Property domain value is null: $($StAccount.StorageAccountName)"
                        Remove-ADComputer -Identity $StAccount.StorageAccountName -server $DomainController.Name `
                            -Confirm:$false -Credential $AzCredential
                        Write-Output "Deleted Computer object: $($StAccount.StorageAccountName)"
                        Write-Output "Starting domain rejoin process for storage account:$($StAccount.StorageAccountName)"
                        Start-StorageAccountDomainJoin -StorageAccountName $StAccount.StorageAccountName `
                            -ResourceGroupName $StAccount.ResourceGroupName
                            -Domain $Domain `
                            -Path $Path 
                }
                elseif ($CheckStorageADObject.PasswordLastSet -lt $PDate -and $ChecstorageADObject -ne $null) {

                        Write-Output "Starting storage account password reset: $($StAccount.StorageAccountName) : $($CheckstorageADObject.PasswordLastSet) "
                        Update-StorageAccountDomainPwd -StorageAccountName $StAccount.StorageAccountName `
                            -ResourceGroupName $StAccount.ResourceGroupName
                            -Domain $Domain
                }
                elseif ($CheckstorageADObject -ne $null -and $StADdomain -ne $null) {



                        # Validate that the storage account AD object has a valid key. It will return a 'True' value if it's valid and a 'False' value if there is amismatch.

                        $KeyMatches = Test-StorageAccountKey -StorageAccountName $StAccount.StorageAccountName `
                        -ResourceGroupName $StAccount.ResourceGroupName `
                        -Domain $Domain

                    Write-Output "Storage account AD object exists: $($StAccount.StorageAccountName) : KeyMatches: $($KeyMatches)"
                    If ($KeyMatches -eq $False) {

                        Write-Output "Test key returned $($KeyMatches). Performing domain rejoin: $($StAccount.StorageAccountName)"
                        Remove-ADComputer -Identity $StAccount.StorageAccountName -server $DomainController.Name `
                            -Confirm:$False -Credential $AzCredential
                        Write-Output "Deleted Computer object: $($StAccount.StorageAccountName)"
                        Write-Output "Starting Domain rejoin process for storage account: $($StAccount.StorageAccountName)"
                        
                        Start-StorageAccountDomainJoin -StorageAccountName $StAccount.StorageAccountName `
                            -ResourceGroupName $StAccount.ResourceGroupName `
                            -Domain $Domain `
                            -Path $Path 
                    }
                } 
                
            }
 
        }

    }

    Write-Output "Script successfully completed"
