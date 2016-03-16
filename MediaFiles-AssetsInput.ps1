<#
.DESCRIPTION
    This runbook creates all assets which required for Disk Integrity process.
     
.ASSETS 
    AzureCredential [Windows PS Credential]:
        A credential containing an Org Id username, password with access to this Azure subscription
        Multi Factor Authentication must be disabled for this credential
    
    VMCredential [Windows PS Credential]:
        A credential containing an username, password with access to Virtual Machine
         
    AzureSubscriptionName: The name of the Azure Subscription
    ResourceName: The name of the StorSimple resource
    StorSimRegKey: The registration key for the StorSimple manager
    StorageAccountName: The storage account name in which the script will be stored
    StorageAccountKey: The access key for the storage account
    SourceDeviceName: The Device which has to be verified disk status
    StorageContainerName: The name of storage container in which the files will be stored
    TargetDeviceName: The Device on which the containers are to be cloned
    VMName: The name of the Virtual machine which has to be used for mount the volumes & verify the disk status.
    VMServiceName: The Cloud service name where Virtual machine is running
    VolumeContainers: A comma separated string of volume containers present on the Device that need to be checked, ex - "VolCon1,VolCon2"
    DirectoryNameFilter: A comma separated string for Director names, ex - "log*,Sam*"
    FileNameFilter: A comma separated string for File names, ex - "sam*.mp4,*.wav,Asset*.*"

.NOTES:
	Multi Factor Authentication must be disabled to execute this runbook
	If a volume doesn't have at least one backup then it'll be skipped to upload the media files.
#>

workflow MediaFiles-AssetsInput
{
    Param
    (
        [parameter(Mandatory=$true, Position=1, HelpMessage="The name of the Azure Subscription")]
		[ValidateNotNullOrEmpty()]
        [string]$AzureSubscriptionName,
        
        [parameter(Mandatory=$true, Position=2, HelpMessage="The name of the StorSimple resource")]
		[ValidateNotNullOrEmpty()]
        [string]$ResourceName,
                
        [parameter(Mandatory=$true, Position=3, HelpMessage="The registration key for the StorSimple manager")]
		[ValidateNotNullOrEmpty()]
        [string]$StorSimRegKey,
        
        [parameter(Mandatory=$true, Position=4, HelpMessage="The storage account name in which the script will be stored")]
		[ValidateNotNullOrEmpty()]
        [string]$StorageAccountName,
        
        [parameter(Mandatory=$true, Position=5, HelpMessage="The access key for the storage account")]
		[ValidateNotNullOrEmpty()]
        [string]$StorageAccountKey,
        
        [parameter(Mandatory=$true, Position=6, HelpMessage="The storage container name in which the files (media) will be stored")]
		[ValidateNotNullOrEmpty()]
        [string]$StorageContainerName,
        
        [parameter(Mandatory=$true, Position=7, HelpMessage="The Device which has to be verified disk status")]
		[ValidateNotNullOrEmpty()]
        [string]$SourceDeviceName,
        
        [parameter(Mandatory=$true, Position=8, HelpMessage="The Device on which the containers are to be cloned")]
		[ValidateNotNullOrEmpty()]
        [string]$TargetDeviceName,
        
        [parameter(Mandatory=$true, Position=9, HelpMessage="The name of the Virtual machine which has to be used for mount the volumes & verify the disk status.")]
		[ValidateNotNullOrEmpty()]
        [string]$VMName,
        
        [parameter(Mandatory=$true, Position=10, HelpMessage="The Cloud service name where Virtual machine is running")]
		[ValidateNotNullOrEmpty()]
        [string]$VMServiceName,
        
        [parameter(Mandatory=$true, Position=11, HelpMessage="A comma separated string of volume containers present on the Device that need to be checked, ex - VolCon1,VolCon2")]
		[ValidateNotNullOrEmpty()]
        [string]$VolumeContainers,
        
        [parameter(Mandatory=$false, Position=12, HelpMessage="A comma separated string for Director names, ex - log*,Sam*")]
		[ValidateNotNullOrEmpty()]
        [string]$DirectoryNameFilter,
        
        [parameter(Mandatory=$false, Position=13, HelpMessage="A comma separated string for File names, ex - (sam).*(\.mp4),(Asset).*(\.mp4)")]
		[ValidateNotNullOrEmpty()]
        [string]$FileNameFilter,

        [parameter(Mandatory=$true, Position=14, HelpMessage="The name of the Aumation account name")]
		[ValidateNotNullOrEmpty()]
        [String]$AutomationAccountName
    )
	
  	# Set empty string if input is null   
    If ([string]::IsNullOrEmpty($DirectoryNameFilter) -eq $false) {
        $DirectoryNameFilter = "*"
    }
    If ([string]::IsNullOrEmpty($FileNameFilter) -eq $false) {
        $FileNameFilter = "*.*"
    }
	   
	# Add all new assets in collection object
    $NewAssetList = @()
    $AssetProp = @{ Name="AzureSubscriptionName"; Value=$AzureSubscriptionName; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="ResourceName"; Value=$ResourceName; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="StorSimRegKey"; Value=$StorSimRegKey; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="StorageAccountName"; Value=$StorageAccountName; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="StorageAccountKey"; Value=$StorageAccountKey; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="StorageContainerName"; Value=$StorageContainerName; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="SourceDeviceName"; Value=$SourceDeviceName; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="TargetDeviceName"; Value=$TargetDeviceName; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="VMName"; Value=$VMName; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="VMServiceName"; Value=$VMServiceName; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="VolumeContainers"; Value=$VolumeContainers; IsMandatory=$true; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="DirectoryNameFilter"; Value=$DirectoryNameFilter; IsMandatory=$false; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
    
    $AssetProp = @{ Name="FileNameFilter"; Value=$FileNameFilter; IsMandatory=$false; }
    $AssetObj = New-Object PSObject -Property $AssetProp
    $NewAssetList += $AssetObj
	
	# Validate all mandatory parameters
	InlineScript 
	{
 		$NewAssetList = $Using:NewAssetList
		$ErrorMessage = [string]::Empty
        
		foreach ($NewAssetData in $NewAssetList) {
			If ($NewAssetData.IsMandatory -and [string]::IsNullOrEmpty($NewAssetData.Value)) { 
	            $ErrorMessage += "$($NewAssetData.Name) cannot be blank. `n" 
	        }
		}
		
        # Display message
		If ([string]::IsNullOrEmpty($ErrorMessage) -eq $false) {
			throw $ErrorMessage
		}
	}
    
    # Fetch basic Azure automation variables
    $AzureCredential = Get-AutomationPSCredential -Name "AzureCredential"
    If ($AzureCredential -eq $null) 
    {
        throw "The AzureCredential asset has not been created in the Automation service."  
    }
    
    # Connect to Azure
    Write-Output "Connecting to Azure"
    $AzureAccount = Add-AzureAccount -Credential $AzureCredential      
    $AzureSubscription = Select-AzureSubscription -SubscriptionName $AzureSubscriptionName          
    If (($AzureSubscription -eq $null) -or ($AzureAccount -eq $null))
    {
        throw "Unable to connect to Azure"
    }
    
    # Fetch asset list in Automation account
    try {
        $AssetList = (Get-AzureAutomationVariable -AutomationAccountName $AutomationAccountName)  
    }
    catch {
        throw "The Automation account ($AutomationAccountName) is not found."
    }
	
	Write-Output "Initiating to create assets"
    foreach ($NewAssetData in $NewAssetList)
    {
        $AssetVariableName = $NewAssetData.Name
        $AssetValue = $NewAssetData.Value
		
		# Print asset name & value
		Write-Output "$AssetVariableName : $AssetValue"
        
        If ($AssetList -ne $null -and (($AssetList) | Where-Object {$_.Name -eq $AssetVariableName}) -ne $null) {
            $asset = Set-AzureAutomationVariable -AutomationAccountName $AutomationAccountName -Name $AssetVariableName -Encrypted $false -Value $AssetValue
            Write-Output "$AssetVariableName asset updated"
        }
        else {
            $asset = New-AzureAutomationVariable -AutomationAccountName $AutomationAccountName -Name $AssetVariableName -Value $AssetValue -Encrypted $false
            Write-Output "$AssetVariableName asset created"
        }
    }
}