## Domain Join a storage account leveraging Azure Automation

Are you looking to take the next step in your cloud journey and pivot away from managing file servers? Why not look at Azure Files!

In short; Azure Files offers fully managed file shares in the cloud that are accessible via the industry standard Server Message Block (SMB) protocol, Network File System (NFS) protocol, and Azure Files REST API. Azure file shares can be mounted concurrently by cloud or on-premises deployments. SMB Azure file shares are accessible from Windows, Linux, and macOS clients. NFS Azure file shares are accessible from Linux or macOS clients. Additionally, SMB Azure file shares can be cached on Windows servers with Azure File Sync for fast access near where the data is being used. The days of managing a fleet of virtual machines hosting hundreds of file shares are now in appearing in the review mirror. This means you don't have to apply software patches or swap out physical disks when they fail any longer.

## Solution Architecture

![Solution Architecture](https://github.com/DarrenTurchiarelli/AzureDomainJoinStorageAccount/blob/main/Images/DomainJoin-SA-v3.png)

|Step | Description                                                                                                                                                               |
|-----|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|1 | User identities that reside within Active Directory are replicated to Azure Active Directory via AD Connect                                                                  |
|2 | The script is stored within this GitHub repository and is either copy/pasted into a new runbook or configured via 'Source Control'                                                          |
|3 | A Storage Account is tagged with the name pair 'Domain:Connected'                                                                                                            |
|4 | The runbook is executed on the Hybrid worker group                                                                                                                           |
|5 | If an issue occurs with the execution of the runbook an alert is sent to the specified Microsoft Teams channel                                                               |
|6 | The Storage account is created as a new object in Active Directory. Note the Domain Controllers can exist in both Azure and On-Premises and the objects are replicated       |
|7 | An administrator connects to a Domain Controller via Azure Bastion to confirm the object has been successfully created                                                       |
|8 | A new file share is created with the appropriate role assignments                                                                                                            |
|9 | A colleague maps the new file share and confirm access                                                                                                                       |


## Getting started

To get started on this journey you will need a few key building blocks; An Azure subscription and line of sight to a domain controller with Microsoft Azure Active Directory Connect which is configured to synchronize user identities to Azure Active Directory (AAD).  From an identities perspective you will need an Active Directory (AD) user with the ‘Enterprise Administrator’ role to configure identity synchronization. To validate the synchronisation is operational, from within the Azure portal, navigate to AAD and within the overview pane you will see a box with the ‘Azure AD Connect’ status. Alternatively, you can select ‘Azure AD connect’ from within blade to see the detailed status. 

![AD Connect](https://github.com/DarrenTurchiarelli/AzureDomainJoinStorageAccount/blob/main/Images/1.png)

Within the Azure portal, it’s time to create an Automation Account (All of these steps can also be completed using Powershell). There are limits, as with most services which are (documented)[Azure subscription limits and quotas - Azure Resource Manager | Microsoft Docs]under the heading ‘Automation limits’. Once you have successfully deployed an Automation account, navigate to ‘Credentials’ within the blade and add a new credential. This identity will be the synchronized identity of a user with permissions to add new objects to AD. Make note of the credential name you create, as you will need this in a later step to setup the schedule.   

![Automation account setup](https://github.com/DarrenTurchiarelli/AzureDomainJoinStorageAccount/blob/main/Images/2.png)

The next step assumes that your domain controllers exist in an on-premises environment (Two thumbs up if you have already moved them to Azure). Navigate to the ‘User/System hybrid worker groups’ in the blade and press the button to create a new group and follow the prompts. When configuring hybrid workers please keep in mind the number of hybrid workers within your worker group for resilience. If your domain controllers are already in Azure then there is no need to provision hybrid workers, further reading [here](https://docs.microsoft.com/en-us/azure/automation/automation-hybrid-runbook-worker).

There are multiple methods of executing runbooks within an automation account and will cover two methods, that i am familiar with. 

The first method is from the blade, select ‘Runbooks’ and then the ‘Create a runbook’ button. For this solution the runbook type is ‘Powershell’ and the runtime version is ‘5.1’. Navigate over to [Domain Join an Azure Storage Account](https://github.com/DarrenTurchiarelli/AAzureDomainJoinStorageAccount) and copy the relevant code and modify the variables according to your environment. If you are not familiar with PowerShell, the areas of interest are: 

Method one can be executed from the blade via ‘Runbooks’ and then ‘Create a runbook’ button. For this solution the runbook type is ‘Powershell’ and the runtime version is ‘5.1’. Navigate to [Domain Join an Azure Storage Account](https://github.com/DarrenTurchiarelli/AzSA-DomainJoin) and copy the relevant code and modify the variables according to your environment. If you are not familiar with PowerShell, the areas of interest are: 


| Line    | Description                                                                                             | 
----------|---------------------------------------------------------------------------------------------------------|
| Line 27 | The help message that explains what inputs are valid                                                    | 
| Line 28 | The list of valid NetBIOS domains that the runbook will accept                                          | 
| Line 36 | The AD domain name                                                                                      | 
| Line 39 | The destination organisational unit (OU) that the storage accounts will reside in, once domain joined   | 
| Line 42 | The Microsoft teams webhook, for notifications to be sent to                                            | 

Once the runbook is saved and published, it's time to test. Navigate to a storage account and add the name pair tag: Domain:Connected. Navigate back to the Azure Automation Account and press the start button and input the two mandatory parameters (DomainName and AzCredentialName) along with the run settings (Hybrid Worker). Once you have the desired result of a domain joined storage account, it's time to setup the schedule from the schedule option within the blade. Set the schedule to run at an interval which suits your environment. Alternatively, you can look at the 'Watcher tasks' option to have the runbook trigger. A watcher task allows you to watch for events and trigger actions. It is comprised of a watcher runbook and an action runbook. The watcher searches for an event and triggers the action when an event occurs. For example, you can watch a folder for new files and trigger an action that backs up those files when they are created.

![Tagged storage account](https://github.com/DarrenTurchiarelli/AzureDomainJoinStorageAccount/blob/main/Images/3.png)

The second method is my preferred option, where possible, as it allows me to store my runbooks within source control. To use this method, from the blade you will need to select 'Source Control' and then press on the 'Add' button

| Property               | Description                                                                                                                                                       |
|------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Source control name	 | A friendly name for the source control. This name must contain only letters and numbers.                                                                          |
| Source control type	 | Type of source control mechanism. Available options are:                                                                                                          |
|                        |       * GitHub                                                                                                                                                    |
|                        |       * Azure DevOps (Git)                                                                                                                                        |
|                        |       * Azure DevOps (TFVC)                                                                                                                                       |
| Repository	         | Name of the repository or project. The first 200 repositories are retrieved. To search for a repository, type the name in the field and click Search on GitHub.   |
| Branch                 | Branch from which to pull the source files. Branch targeting isn't available for the TFVC source control type.                                                    |
| Folder path	         | Folder that contains the runbooks to synchronize, for example, /Runbooks. Only runbooks in the specified folder are synchronized. Recursion isn't supported.      |
| Auto Sync1	         | Setting that turns on or off automatic synchronization when a commit is made in the source control repository.                                                    |
| Publish Runbook	     | Setting of On if runbooks are automatically published after synchronization from source control, and Off otherwise.                                               |
| Description	         | Text specifying additional details about the source control.                                                                                                      |



## A little context on what the runbook does under the cover:

- Creates a computer object in Active Directory sets the properties of the storage account with domain configuration 
- Queries all subscriptions within an Azure tenant and subsequently queries all Storage Accounts (SA) for the tag key pair value 'Domain:Connected'
- Validates within Active Directory that the computer object exists
- Validates the storage account to generate a new key with the name 'kerb1'
- Creates a user identity in Active Directory using the 'kerb1' key as the identity's password
- Set the Service Principal value of the new identity to be: cifs/<StorageAccountName>.file.core.windows.net.
- Updates the kerb value and password for computer object every 14 days 
- Validates the AD object and kerb values match and reset in the event of a mismatch

And voila! The storage account has now been joined to the domain. From here you can look at leveraging Azure File Sync to get you files/folders into an Azure storage account. Finally jump over to the following link to assign [permissions](https://docs.microsoft.com/en-us/azure/storage/files/storage-files-identity-ad-ds-assign-permissions?tabs=azure-portal) 😊

![Domain joined storage account](https://github.com/DarrenTurchiarelli/AzureDomainJoinStorageAccount/blob/main/Images/5.png)


## END-TO-END POC | HIGH LEVEL STEPS

    - Azure Subscription 
        
    - Microsoft Azure Active Directory Connect - https://www.microsoft.com/en-us/download/details.aspx?id=47594
        
    - Domain Controller (DC) - If you are building a POC you can deploy a DC with a VNet/Load Balancer etc from here - https://github.com/mikepfeiffer/azure-domain-controller
            
    - Enable 'Azure Bastion' on this subnet to allow you to connect to the domain controller. If you do not have an NSG on your VM subnet, it is recommended to provision one. Add service tag: Load Balancer 
        
    - On the DC, launch 'Server Manager' and under 'Features' enable 'Remote Access Server Toolkit'
        
    - On the DC, Enable TLS 1.2 - https://docs.microsoft.com/en-us/azure/active-directory/hybrid/reference-connect-tls-enforcement 
        
    - On the DC, install Microsoft Azure Active Directory Connect and run the express configuration with an account that has the role 'Enterprise Administrator'
        
    - Within the Azure portal, navigate to 'Automation Accounts' and create a new account
        
    - Attach the relevant runbook from this repository
        
    - Build a Hybrid Worker virtual machine from the 'Hybrid Workers Group' in the blade
        
    - Run the following on your hybrid worker: Install-WindowsFeature -Name "RSAT-AD-PowerShell" -IncludeAllSubFeature
        
    - Add the following PSCredentialTools module from the 'Modules' section. 
        
    - Validate the Az modules are imported/installed on your hybrid worker
        
    - Validate the account running the runbook has read access at a minimum over the scope of objects
        
    - Create a new Storage account and tag it with the key pair value 'Domainjoin:TRUE' 
        
    - Run the runbook and validate that the storage account can join the domain
        
    - Set a schedule for how often you want this runbook to run and voila you will have a domain joined storage account! 
        

## DISCLAIMER
The sample scripts are not supported under any Microsoft standard support program or service. The sample scripts are provided AS IS without warranty of any kind. Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose. The entire risk arising out of the use or performance of the sample scripts and documentation remains with you. In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages.
