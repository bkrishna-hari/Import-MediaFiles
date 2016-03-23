<#
.DESCRIPTION
    This runbook starts the StorSimple Virtual Appliance (SVA) & Virtual Machine (VM) in case these are in a shut down state. 
    This runbook reads all volumes info based on VolumeContainers asset.  After that it clones the fetched volumes on to the target Device.
    This runbook creates a script and stores it in a storage account. This script will connect the iSCSI target and mount the volumes on the VM. It then uses the Custom VM Script Extension to run the script on the VM.
    This runbook verifies the CHKDSK result on all mounted volumes. Once the CHKDSK execution completes.
    This runbook deletes all the volumes and volume contaienrs on the target device.
    This runbook also shuts downs the SVA & VM.
     
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
	If a volume doesn't have at least one backup then it'll be skipped to verify data integrity
	If a volume already exists in the target device then it'll be skipped from cloning
#>

workflow Trigger-MediaFiles-Copy
{
    $AcrName = "VMName-vm-acr"
    $SourceBlob = "https://StorageAccountName.blob.core.windows.net/"
    $AzCopyLogFile = "C:\Users\Public\Documents\AzCopy-DriveLetter.log"
    $AzCopyLogFolderPath = ($AzCopyLogFile | Split-Path)
    $ScriptContainer = "scriptcontainer"  # The name of the Storage Container in which the script will be stored
    
    # TImeout inputs
    $SLEEPTIMEOUT = 60 # Value in seconds 
    $SLEEPTIMEOUTSMALL = 10 # Value in seconds
    $SLEEPTIMEOUTLARGE = 300 # Value in seconds
    
    # Fetch all Automation Variable data
    Write-Output "Fetching assets info"
    $AzureCredential = Get-AutomationPSCredential -Name "AzureCredential"
    If ($AzureCredential -eq $null) 
    {
        throw "The AzureCredential asset has not been created in the Automation service."  
    }
        
    $VMCredential = Get-AutomationPSCredential -Name "VMCredential"
    If ($VMCredential -eq $null) 
    {
        throw "The VMCredential asset has not been created in the Automation service."  
    }
    
    $SubscriptionName = Get-AutomationVariable –Name "AzureSubscriptionName"
    if ($SubscriptionName -eq $null) 
    { 
        throw "The AzureSubscriptionName asset has not been created in the Automation service."  
    }

    $ResourceName = Get-AutomationVariable –Name "ResourceName" 
    if ($ResourceName -eq $null) 
    { 
        throw "The ResourceName asset has not been created in the Automation service."  
    }
    
    $RegistrationKey = Get-AutomationVariable -Name "StorSimRegKey"
    if ($RegistrationKey -eq $null) 
    { 
        throw "The StorSimRegKey asset has not been created in the Automation service."  
    }
    
    $StorageAccountName = Get-AutomationVariable –Name "StorageAccountName" 
    if ($StorageAccountName -eq $null) 
    { 
        throw "The StorageAccountName asset has not been created in the Automation service."  
    }
    
    $SourceBlob = $SourceBlob.Replace("StorageAccountName", $StorageAccountName)
    If ($SourceBlob -ne $null -and $SourceBlob.EndsWith("/") -eq $false) 
    {
        $SourceBlob += "/"
    }
        
    $StorageAccountKey = Get-AutomationVariable –Name "StorageAccountKey" 
    if ($StorageAccountKey -eq $null) 
    { 
        throw "The StorageAccountKey asset has not been created in the Automation service."  
    }
        
    $StorageContainerName = Get-AutomationVariable –Name "StorageContainerName" 
    if ($StorageContainerName -eq $null)
    { 
        throw "The StorageContainerName asset has not been created in the Automation service."  
    }
    $StorageContainerUrl = ($SourceBlob + $StorageContainerName)
    
    $ContainerNames = Get-AutomationVariable –Name "VolumeContainers"
    if ($ContainerNames -eq $null) 
    { 
        throw "The VolumeContainers asset has not been created in the Automation service."  
    }
    elseIf($ContainerNames -eq "" -or $ContainerNames.Length -eq 0) 
    {
        throw "The VolumeContainers asset left blank. Please provide valid data"
    }
    $VolumeContainers =  ($ContainerNames.Split(",").Trim() | sort)
     
    $DeviceName = Get-AutomationVariable –Name "SourceDeviceName" 
    if ($DeviceName -eq $null)
    { 
        throw "The SourceDeviceName asset has not been created in the Automation service."  
    }

    $TargetDeviceName= Get-AutomationVariable –Name "TargetDeviceName" 
    if ($TargetDeviceName -eq $null)
    {
        throw "The TargetDeviceName asset has not been created in the Automation service."  
    }

    $VMName = Get-AutomationVariable –Name "VMName"
    if ($VMName -eq $null) 
    { 
        throw "The VMName asset has not been created in the Automation service."  
    }

    $VMServiceName = Get-AutomationVariable –Name "VMServiceName"
    if ($VMServiceName -eq $null) 
    { 
        throw "The VMServiceName asset has not been created in the Automation service."  
    }
	
    $DirectoryNameFilter = @()
    $DirectoryNameFilterString = Get-AutomationVariable –Name "DirectoryNameFilter"
    If ([string]::IsNullOrEmpty($DirectoryNameFilterString) -eq $false -and ($DirectoryNameFilterString).Trim() -eq "*") {
    	$DirectoryNameFilterString = $DirectoryNameFilterString.Trim().Replace("*", "")
    }
    If ([string]::IsNullOrEmpty($DirectoryNameFilterString) -eq $false) {
        $DirectoryNameFilter = ($DirectoryNameFilterString.Trim().Split(",").Trim() | sort)
    }
    
    $FileNameFilter = @()
    $FileNameFilterString = Get-AutomationVariable –Name "FileNameFilter"
    If ([string]::IsNullOrEmpty($FileNameFilterString) -eq $false) {
        $FileNameFilter = ($FileNameFilterString.Trim().Split(",").Trim() | sort)
    }
    else {
        $FileNameFilter = @("*.*") 
    }
    
    Write-Output "DirectoryNameFilter: $DirectoryNameFilter"
    Write-Output "FileNameFilter: $FileNameFilter"
	
    # Remove VM service extension 
    $VMServiceName = (($VMServiceName -replace ".cloudapp.net", "") -replace "http://", "")

    # Connect to Azure
    Write-Output "Connecting to Azure"
    $AzureAccount = Add-AzureAccount -Credential $AzureCredential      
    $AzureSubscription = Select-AzureSubscription -SubscriptionName $SubscriptionName          
    If (($AzureSubscription -eq $null) -or ($AzureAccount -eq $null)) 
    {
        throw "Unable to connect to Azure"
    }
    
    # Connect to StorSimple 
    Write-Output "Connecting to StorSimple"                
    $StorSimpleResource = Select-AzureStorSimpleResource -ResourceName $ResourceName -RegistrationKey $RegistrationKey
    If ($StorSimpleResource -eq $null) 
    {
        throw "Unable to connect to StorSimple"
    }
    
    # Set Current Storage Account for the subscription
    Write-Output "Setting the storage account for the subscription"
    try {
        Set-AzureSubscription -SubscriptionName $SubscriptionName -CurrentStorageAccountName $StorageAccountName
    }
    catch {
        throw "Unable to set the storage account for the subscription"
    }
    
    $TargetDevice = Get-AzureStorSimpleDevice -DeviceName $TargetDeviceName
    if ($TargetDevice -eq $null) 
    {
        throw "Target device $TargetDeviceName does not exist"
    }

    $TargetVM = Get-AzureVM -Name $VMName -ServiceName $VMServiceName
    if ($TargetVM -eq $null)
    {
        throw "VMName or VMServiceName asset is incorrect"
    }
    
    # Add all devices & VMs which are to be Turn on when the process starts & Turn off in the end 
    $SystemList = @()
    $SVAProp = @{ Type="SVA"; Name=$TargetDeviceName; ServiceName=$TargetDeviceName; Status=$TargetDevice.Status }
    $SVAObj = New-Object PSObject -Property $SVAProp
    $SystemList += $SVAObj
    $VMProp = @{ Type = "VM"; Name=$VMName; ServiceName=$VMServiceName; Status=$TargetVM.Status }
    $VMObj = New-Object PSObject -Property $VMProp
    $SystemList += $VMObj
    
    # Turning the SVA on
    Write-Output "Attempting to turn on the SVA & VM"
    foreach ($SystemInfo in $SystemList)
    {
        InlineScript
        {
            $SystemInfo = $Using:SystemInfo
            $Name = $SystemInfo.Name
            $ServiceName = $SystemInfo.ServiceName
            $SystemType = $SystemInfo.Type
            $SLEEPTIMEOUTSMALL = $Using:SLEEPTIMEOUTSMALL
            
            $status = "Offline"
            If ($SystemInfo.Status -eq "Online" -or $SystemInfo.Status -eq "ReadyRole") { 
                $status = "Online"
            }
        
            if ($status -ne "Online" )
            {
                Write-Output " Starting the $SystemType ($Name)"
                $RetryCount = 0
                while ($RetryCount -lt 2)
                {
                    $Result = Start-AzureVM -Name $Name -ServiceName $ServiceName 
                    if ($Result.OperationStatus -eq "Succeeded")
                    {
                        Write-Output "  $SystemType succcessfully turned on ($Name)"   
                        break
                    }
                    else
                    {
                        if ($RetryCount -eq 0) {
                            Write-Output "  Retrying turn on the $SystemType ($Name)"
                        }
                        else {
                            throw "  Unable to start the $SystemType ($Name)"
                        }
                                    
                        # Sleep for 10 seconds before trying again                 
                        Start-Sleep -s $SLEEPTIMEOUTSMALL
                        $RetryCount += 1   
                    }
                }
                
                $TotalTimeoutPeriod = 0
                while($true)
                {
                    Start-Sleep -s $SLEEPTIMEOUTSMALL
                    If ($SystemType -eq "SVA") {
                        $SVA =  Get-AzureStorSimpleDevice -DeviceName $Name
                        if($SVA.Status -eq "Online")
                        {
                            Write-Output "  SVA ($Name) status is now online"
                            break
                        }
                    }
                    elseIf ($SystemType -eq "VM") {
                        $VM =  Get-AzureVM -Name $Name -ServiceName $ServiceName
                        if($VM.Status -eq "ReadyRole")
                        {
                            Write-Output "  VM ($Name) is now ready state"
                            break
                        }
                    }
                    
                    $TotalTimeoutPeriod += $SLEEPTIMEOUTSMALL
                    if ($TotalTimeoutPeriod -gt 540) #9 minutes
                    {
                        throw "  Unable to bring the $SystemType online"
                    }
                }
            }
            elseIf ($SystemType -eq "SVA") {
                Write-Output " SVA ($Name) is online"
            }
            elseIf ($SystemType -eq "VM") {
                Write-Output " VM ($Name) is ready state"
            }
        }
    }
    
    Write-Output "Fetching VM WinRMUri"
    $VMWinRMUri = InlineScript { 
        try {
            # Get the Azure certificate for remoting into this VM
            $winRMCert = (Get-AzureVM -ServiceName $Using:VMServiceName -Name $Using:VMName | select -ExpandProperty vm).DefaultWinRMCertificateThumbprint   
            $AzureX509cert = Get-AzureCertificate -ServiceName $Using:VMServiceName -Thumbprint $winRMCert -ThumbprintAlgorithm sha1
    
            # Add the VM certificate into the LocalMachine
            if ((Test-Path Cert:\LocalMachine\Root\$winRMCert) -eq $false)
            {
                # "VM certificate is not in local machine certificate store - adding it"
                $certByteArray = [System.Convert]::fromBase64String($AzureX509cert.Data)
                $CertToImport = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 -ArgumentList (,$certByteArray)
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store "Root", "LocalMachine"
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
                $store.Add($CertToImport)
                $store.Close()
            }
    		
    		# Return the WinRMUri so that it can be used to connect to the VM
    		Get-AzureWinRMUri -ServiceName $Using:VMServiceName -Name $Using:VMName
        }
        catch {
            throw "Unable to fetch VM WinRMUri"
        }     
    }
    
    if ($VMWinRMUri -eq $null) {
        throw "Unable to fetch VM WinRMUri"
    }
    
    Write-Output "Install AzCopy & fetch VM's - Inititator name"
    $VMIQN = InlineScript
    {
        Invoke-Command -ConnectionUri $Using:VMWinRMUri -Credential $Using:VMCredential -ScriptBlock {
            param([Int]$SLEEPTIMEOUTSMALL)
			
			# Install AzCopy
            $source = "http://aka.ms/downloadazcopy"
            $destination = "C:\Users\Public\Downloads\AzCopy.msi" 
            $AzCopyPath = "C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy\AzCopy.exe"
			
			# Trigger to download AzCopy software
			Invoke-WebRequest $source -OutFile $destination
			
			#wait till the file is downloaded
            while ($true)
            {
                $checkForFile = (Test-Path $destination)
                if ($checkForFile) {
                    break
                }
                else {
                    Start-Sleep -s $SLEEPTIMEOUTSMALL
                }                        
            }
			
            # Execute the AzCopy exe
            Start-Process "C:\Windows\System32\msiexec.exe" -ArgumentList "/i $destination /qn" -wait
							
            # Starting the iSCSI service
            Start-Service msiscsi
            Start-Sleep -s $SLEEPTIMEOUTSMALL
			
			# Set default setting
            Set-Service msiscsi -StartupType "Automatic"
            
            # Getting VM initiator name
            $IQN = (Get-InitiatorPort).NodeAddress
            
            # Output of InlineScript
            $IQN
        } -Argumentlist $Using:SLEEPTIMEOUTSMALL
    }
    
    If ($VMIQN -eq $NUll ) {
        throw "Unable to fetch the ACR of VM ($VMName)"
    }
    else 
    {
        # Replace actual VM Name
        $AcrName = $AcrName -replace "VMName", "$VMName"
        
        # Fetch existing ACR details
        $AvailableACRList = Get-AzureStorSimpleAccessControlRecord        
        $VMAcr = ($AvailableACRList | Where-Object { $_.InitiatorName -eq $VMIQN -or $_.Name -eq $AcrName })
        If ($VMAcr -eq $null)
        {
            Write-Output "Adding ACR ($AcrName) to the resource"
            $AcrCreation=New-AzureStorSimpleAccessControlRecord -ACRName $AcrName -IQNInitiatorName $VMIQN -WaitForComplete -ErrorAction:SilentlyContinue
            If ($AcrCreation -eq $null) {
                throw "ACR ($AcrName) could not be added to the resource"
            }
        
            $VMAcr = Get-AzureStorSimpleAccessControlRecord -ACRName $AcrName
        }
        
        $AcrName = $VMAcr.Name
    }
    
    Write-Output "Attempting to fetch the volume list"
    InlineScript
    {
        $DeviceName = $Using:DeviceName
        $TargetDeviceName = $Using:TargetDeviceName
        $VolumeContainers = $Using:VolumeContainers
        $VMAcr = $Using:VMAcr
        $SLEEPTIMEOUTSMALL = $Using:SLEEPTIMEOUTSMALL
     
        $VolList = @()   
        $TotalVolumesCount = 0
        foreach ($ContainerName in $VolumeContainers)
        {
            $ContainerData = Get-AzureStorSimpleDeviceVolumeContainer -DeviceName $DeviceName -VolumeContainerName $ContainerName -ErrorAction:SilentlyContinue
            if ($ContainerData -eq $null) {
                throw "  Volume container ($ContainerName) not exists in Device ($DeviceName)"
            }
            
            $TotalVolumesCount += $ContainerData.VolumeCount
            If ($ContainerData.VolumeCount -eq 0) {
                Write-Output "  Volume container ($ContainerName) has zero volumes"
                continue
            }
            
            $volumes = Get-AzureStorSimpleDeviceVolumeContainer -DeviceName $DeviceName -VolumeContainerName $ContainerName | Get-AzureStorSimpleDeviceVolume -DeviceName $DeviceName -ErrorAction:SilentlyContinue
            foreach ($volume in ($volumes | Sort-Object {$_.Name}))
            { 
                $VolumeProp = @{ ContainerName=$ContainerName; Volume=$volume; HasBackup=$null; IsClonedAlready=$false }
                $VolObj = New-Object PSObject -Property $VolumeProp
                $VolList += $VolObj
            }
        }

        if ($TotalVolumesCount -eq 0) {
            throw "  No volumes exist in the containers"
        }
        
        # Clone all the volumes in the volume containers as per the latest backup
        Write-Output "Triggering and waiting for clone(s) to finish"
        foreach ($VolumeObj in $VolList)
        {
            $volume = $VolumeObj.Volume
            $targetdevicevolume = Get-AzureStorSimpleDeviceVolume -DeviceName $TargetDeviceName -VolumeName $volume.Name -ErrorAction:SilentlyContinue
            if ($targetdevicevolume -ne $null)
            {
                # Skipped volume cloning due to cloned volume already available; it may not be deleted in previous process
                $VolumeObj.IsClonedAlready = $true
                Write-Output "  Volume ($($volume.Name)) already exists" 
                continue
            }

            $backups = $volume | Get-AzureStorSimpleDeviceBackup -DeviceName $DeviceName | Where-Object {$_.Type -eq "CloudSnapshot"} | Sort "CreatedOn" -Descending
            if ($backups -eq $null) {
                $VolumeObj.HasBackup = $false
                Write-Output "  *No backup exists for the volume ($($volume.Name)) - volume container ($($VolumeObj.ContainerName))"
                continue
            }

            # Gives the latest backup
            $latestBackup = $backups[0]
            $VolumeObj.HasBackup = $true
            $VolumeObj.IsClonedAlready = $false
            
            # Match the volume name with the volume data inside the backup
            $snapshots = $latestBackup.Snapshots
            $snapshotToClone = $null
            foreach ($snapshot in $snapshots)
            {
                if ($snapshot.Name -eq $volume.name)
                {
                    $snapshotToClone = $snapshot
                    break
                }
            }

            $jobID = Start-AzureStorSimpleBackupCloneJob -SourceDeviceName $DeviceName -TargetDeviceName $TargetDeviceName -BackupId $latestBackup.InstanceId -Snapshot $snapshotToClone -CloneVolumeName $volume.Name -TargetAccessControlRecords $VMAcr -Force
            if ($jobID -eq $null)
            {
                throw "  Clone couldn't be initiated for volume ($($volume.Name)) - volume container ($($VolumeObj.ContainerName))"
            }
                
            $checkForSuccess = $true
            while ($true)
            {
                $status = Get-AzureStorSimpleJob -InstanceId $jobID
                Start-Sleep -s $SLEEPTIMEOUTSMALL
                if ( $status.Status -ne "Running")
                {
                    if ( $status.Status -ne "Completed") {
                        $checkForSuccess = $false
                    }
                    break
                }
            }

            if ($checkForSuccess) {
                Write-Output "  Clone successful for volume ($($volume.Name))"
            }
            else {
                throw "  Clone unsuccessful for volume ($($volume.Name))"
            }
        }
    }
    
    # Fetching IQN & IP Address of the Virtual device
    $SVAIP = (Get-AzureVM -ServiceName $TargetDeviceName -Name $TargetDeviceName).IpAddress
    If ($SVAIP -eq $null) {
        throw "Unable to get the IP Address of Azure VM ($TargetDeviceName)"
    }
    
    $SVAIQN = (Get-AzureStorSimpleDevice -DeviceName $TargetDeviceName).TargetIQN
    If ($SVAIQN -eq $null) {
        throw "Unable to fetch IQN of the SVA ($TargetDeviceName)"
    }
    
    # Create the iSCSI target portal and mount the volumes, return the drive letters of the mounted StorSimple volumes
    Write-Output "Create the iSCSI target portal and mount the volumes"
    
    $RetryCount = 0
    while ($RetryCount -lt 2)
    {
        try
        {
            $drives = InlineScript {
                Invoke-Command -ConnectionUri $Using:VMWinRMUri -Credential $Using:VMCredential -ScriptBlock { 
                    param([String]$SVAIP, [String]$SVAIQN, [Int]$SLEEPTIMEOUTSMALL)
                    
                        # Disconnect all connected hosts
                        Get-IscsiTarget | Disconnect-IscsiTarget -Confirm:$false -ErrorAction:SilentlyContinue
                        Start-Sleep -s $SLEEPTIMEOUTSMALL
                        
                        # Remove all connected hosts
                        Get-IscsiTargetPortal | Remove-IscsiTargetPortal -Confirm:$false -ErrorAction:SilentlyContinue
                        Start-Sleep -s $SLEEPTIMEOUTSMALL
                        
                        Update-StorageProviderCache
                        Update-HostStorageCache 
                        Start-Sleep -s $SLEEPTIMEOUTSMALL
                        
                        # Collect drive list
                        $initialdisks = (Get-Volume | Where-Object {$_.FileSystem -eq 'NTFS'})
                        if ($initialdisks -eq $null) {
                            throw "Unable to get the volumes on the VM"
                        }
                        
                        $newportal = New-IscsiTargetPortal -TargetPortalAddress $SVAIP -ErrorAction:SilentlyContinue
                        If ($newportal -eq $null) {
                            throw "Unable to create a new iSCSI target portal"
                        }
                        
                        $connection = Connect-IscsiTarget -NodeAddress $SVAIQN -IsPersistent $true -ErrorAction:SilentlyContinue
                        $sess = Get-IscsiSession
                        If ($sess -eq $null) {
                            throw "Unable to connect the iSCSI target (SVA)"
                        }
                        
                        Update-StorageProviderCache
                        Update-HostStorageCache
                        Start-Sleep -s $SLEEPTIMEOUTSMALL
                                    
                        # Collect drive list after mount
                        $finaldisks = (Get-Volume | Where-Object {$_.FileSystem -eq 'NTFS'})
                        if ($finaldisks -eq $null) {
                            throw "Unable to get the volumes after mounting"
                        }
                        
                        $drives = Compare-Object $initialdisks $finaldisks -Property 'DriveLetter' | where {$_.SideIndicator -eq "=>"} | Sort DriveLetter | % {$_.DriveLetter + ":\"}
                        
                        # Output of InlineScript
                        ($drives -Join ",")
                        
                } -Argumentlist $Using:SVAIP,$Using:SVAIQN,$Using:SLEEPTIMEOUTSMALL
                
            }
        } catch [Exception] {
            Write-Output $_.Exception.GetType().FullName;
            throw $_.Exception.Message;
        }
        
        if ($drives -eq $null -or $drives.Length -eq 0) {
            if ($RetryCount -eq 0) {
                Write-Output "  Retrying for drive letters of the mounted StorSimple volumes"
            }
            else {
                Write-Output "  Unable to read the StorSimple drives"
            }
            
            # Sleep for 10 seconds before trying again
            Start-Sleep -s $SLEEPTIMEOUTSMALL
            $RetryCount += 1
        }
        else {
            $RetryCount = 2 # To stop the iteration; similar as 'break' statement
        }
    }
    
    if ($drives -eq $null -or $drives.Length -eq 0) {
        throw "Unable to read StorSimple drives"
    }
    
    Write-Output "Drives: $drives"
    
    # Set Drivelist
    $DrivesList = $drives.Split(",").Trim()
    
    Write-Output "Fetching matched folders/files..."
    $content = InlineScript {
        Invoke-Command -ConnectionUri $Using:VMWinRMUri -Credential $Using:VMCredential -ScriptBlock { 
            param([Int]$SLEEPTIMEOUT,[string[]]$DrivesList,[string]$StorageAccountKey,[string]$StorageContainerUrl,[string]$AzCopyLogFile,[string]$AzCopyLogFolderPath,[string[]]$DirectoryNameFilter,[string[]]$FileNameFilter)
                If ($StorageContainerUrl -ne $null -and $StorageContainerUrl.EndsWith("/") -eq $false) {
            		$StorageContainerUrl += "/"
            	}
            			                
            	$listOfDirectories = @()
            	if ($DirectoryNameFilter -ne $null -and $DirectoryNameFilter.Length -gt 0)
            	{
            		foreach ($drive in $DrivesList) {
            			foreach ($directoryFilter in $DirectoryNameFilter) {
            			    $listOfDirectories += Get-ChildItem -Directory -Path $drive -Filter $directoryFilter -Recurse | Sort
            			}
            		}
            	}
            			           
            	$DirectoryList = @()     
            	$listOfDirectories = $listOfDirectories | Select FullName,PSDrive -Unique
            	if ($listOfDirectories -eq $null) {
            		$listOfDirectories = $DrivesList
            	}
            	else {
            		# Remove sub-directories if parent directory exists
            		$directoryName = ""
            		foreach ($directoryData in $listOfDirectories) {
            			$directoryName = $directoryData.FullName
            			$ParentDirectory = $directoryData.FullName
            			if($directoryName.IndexOf("\\") -ne $directoryName.LastIndexOf("\\")) {
            			    $ParentDirectory = $directoryName.SubString(0,$directoryName.LastIndexOf("\\"))
            			}
            			
            			if(($DirectoryList | Where-Object {$_.FullName -eq $ParentDirectory}) -eq $null) {
            			    $DirectoryList += $directoryData
            			}
            		}
            			
            		$listOfDirectories = $DirectoryList
            	}
            			
            	$azcopyfilescontent = $null
            	$IsJournalFileAdded = $false
            	$JournalfolderPath = $AzCopyLogFolderPath + "journalfolder-$(Get-Date -format MMddyyyyhhmmss)\"
            	foreach ($directoryData in $listOfDirectories)
            	{
                    $driveLetter = $directoryData
                    $directoryFullPath = $directoryData
                    $directoryPath = ($directoryFullPath -replace ":\\", "")
                    If ($directoryData.PsDrive -ne $null) {
            		    $driveLetter = $directoryData.PsDrive.ToString()
                        $directoryFullPath = $directoryData.FullName
            		    $directoryPath = (($directoryFullPath -replace ":\\", "/") -replace "\\", "/")
                    }
            
            		$LogFileName = ($AzCopyLogFile -replace "DriveLetter", $directoryPath)	        
            			        
            		if ($azcopyfilescontent -eq $null) {
            			# Join Folder path & filename
            			$AzCopyLogFileFormat = (Split-Path $AzCopyLogFile -Leaf) -replace "DriveLetter", "*"
            			                                                
            			# Delete all existing logs & ps files
            			$azcopyfilescontent = "# Delete all available AzCopy log files `n "
            			$azcopyfilescontent += "Get-ChildItem `'$AzCopyLogFolderPath`' `'$AzCopyLogFileFormat`' -Force | Remove-Item -Confirm:`$false -Force; `n "
            			                       
            			# Small delay before create script file
            			$azcopyfilescontent += "Start-Sleep -s $SLEEPTIMEOUT `n `n "
            			                                         
            			$azcopyfilescontent += "# Trigger AzCopy `n "
            			$azcopyfilescontent += "cd 'C:\Program Files (x86)\Microsoft SDKs\Azure\AzCopy' `n "
            		}
            			
            		foreach ($fileNameFilterValue in $FileNameFilter)
            		{
            			if ($IsJournalFileAdded -eq $false) {
            			    $azcopyfilescontent += ".\AzCopy.exe /Source:`'$($directoryFullPath)`' /Dest:'$StorageContainerUrl$($directoryPath + "/")' /DestKey:`'$StorageAccountKey`' /Pattern:`'$fileNameFilterValue`' /S /Y /XO /Z:`'$JournalfolderPath`' /V:`'$LogFileName`' `n " 
            			    $IsJournalFileAdded = $true
            			}
            			else {
            			    $azcopyfilescontent += ".\AzCopy.exe /Source:`'$($directoryFullPath)`' /Dest:'$StorageContainerUrl$($directoryPath + "/")' /DestKey:`'$StorageAccountKey`' /Pattern:`'$fileNameFilterValue`' /S /Y /XO /V:`'$LogFileName`' `n "
            			}
            		}
            	}
                
                # Output for Inline-Command script    
                $azcopyfilescontent
                
        } -Argumentlist $Using:SLEEPTIMEOUT,$Using:DrivesList,$Using:StorageAccountKey,$Using:StorageContainerUrl,$Using:AzCopyLogFile,$Using:AzCopyLogFolderPath,$Using:DirectoryNameFilter,$Using:FileNameFilter
    }
    
    If ($content -eq $null -or $content.Length -eq 0) {
        throw "No files match your search."
    }
    
    Write-Output "Attempting to trigger AzCopy"
    InlineScript 
    {
        $ScriptContainer = $Using:ScriptContainer
        $VMName = $Using:VMName
        $VMServiceName = $Using:VMServiceName
        $StorageAccountName = $Using:StorageAccountName
        $StorageAccountKey = $Using:StorageAccountKey
	$StorageContainerName = $Using:StorageContainerName
        $AzCopyLogFile = $Using:AzCopyLogFile
        $AzCopyLogFolderPath = $Using:AzCopyLogFolderPath
        $content = $Using:content
		$AzCopyLogFolderPath = $Using:AzCopyLogFolderPath
		$AzCopyLogFile = $Using:AzCopyLogFile
        
        # Convert to lower case coz volume container name allows lower case letters, numbers & hypens only
        $ScriptContainer = $ScriptContainer.ToLower()
         
        # Create Storage Account Credential
        $sac = Get-AzureStorSimpleStorageAccountCredential -StorageAccountName $StorageAccountName -ErrorAction:SilentlyContinue 
        If ($sac -eq $null) {
            $sac = New-SSStorageAccountCredential -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey -UseSSL $false -ErrorAction:SilentlyContinue -WaitForComplete
            if ($sac -eq $null) {
                throw "  Unable to create a Storage Account Credential ($StorageAccountName)"
            }
        }
		
        $context = New-AzureStorageContext -StorageAccountName $StorageAccountName -StorageAccountKey $StorageAccountKey
        if ($context -eq $null) {
            throw "  Unable to create a new storage context"
        }
        
        $container = Get-AzureStorageContainer -Name $ScriptContainer -Context $context -ErrorAction:SilentlyContinue
        if ($container -eq $null) {
            $newcontainer = New-AzureStorageContainer -Name $ScriptContainer -Context $context
            if ($newcontainer -eq $null) {
                throw "  Unable to create a container to store the script ($ScriptContainer)"
            }
        }
        
        $storagecontainer = Get-AzureStorageContainer -Name $StorageContainerName -Context $context -ErrorAction:SilentlyContinue
        if ($storagecontainer -eq $null) {
            $newstoragecontainer = New-AzureStorageContainer -Name $StorageContainerName -Context $context
            if ($newstoragecontainer -eq $null) {
                throw "  Unable to create a storage container to store the media files ($StorageContainerName)"
            }
        }
        
        $ScriptName = 'AzCopy-Files-' + $VMName + "-$(Get-Date -format MMddyyyyhhmm).ps1"
        $Scriptfilename = "C:\AzCopy-FilesList-" + $VMName + "-$(Get-Date -format MMddyyyyhhmm).ps1"
        $content | Set-Content $Scriptfilename
        
        $uri = Set-AzureStorageBlobContent -Blob $ScriptName -Container $ScriptContainer -File $Scriptfilename -context $context -Force
        if ($uri -eq $null) 
        {
            throw "Unable to Write script to the container ($Scriptfilename)"
        }
        $sasuri = New-AzureStorageBlobSASToken -Container $ScriptContainer -Blob $ScriptName -Permission r -FullUri -Context $context
        if ($sasuri -eq $null) 
        {
            throw "Unable to get the URI for the script ($ScriptContainer)"
        }
        $AzureVM = Get-AzureVM -ServiceName $VMServiceName -Name $VMName       
        if ($AzureVM -eq $null) 
        {
            throw "Unable to access the Azure VM ($VMName)"
        }
        $extension = $AzureVM.ResourceExtensionStatusList | Where-Object {$_.HandlerName -eq "Microsoft.Compute.CustomScriptExtension"}
        if ($extension -ne $null) 
        {
            Write-Output "  Uninstalling custom script extension" 
            $result = Set-AzureVMCustomScriptExtension -Uninstall -ReferenceName CustomScriptExtension -VM $AzureVM | Update-AzureVM
        }
                           
        Write-Output "  Installing custom script extension" 
        $result = Set-AzureVMExtension -ExtensionName CustomScriptExtension -VM $AzureVM -Publisher Microsoft.Compute -Version 1.7 | Update-AzureVM    
                                        
        Write-Output "  Running script on the VM"         
        $result = Set-AzureVMCustomScriptExtension -VM $AzureVM -FileUri $sasuri -Run $ScriptName | Update-AzureVM
    }
	
    # Add checkpoint even If the runbook is suspended by an error, when the job is resumed, 
    # it will resume from the point of the last checkpoint set.
    Checkpoint-Workflow

    # Sleep for 60 seconds before initiate to verify the AzCopy status
    Start-Sleep -s $SLEEPTIMEOUT
	    
    Write-Output "Attempting to verify AzCopy status"
    Write-Output "AzCopy log file location: $AzCopyLogFolderPath"
    $HasChkDskFailures = $false
    $IsAzCopyExecutionRunning = $true
    While ($IsAzCopyExecutionRunning)
    {
        $IsAzCopyExecutionRunning = InlineScript 
        {
            Invoke-Command -ConnectionUri $Using:VMWinRMUri -Credential $Using:VMCredential -ScriptBlock {
                # Read process list
                $AzCopyPrcessObject = Get-Process | Where-Object { $_.ProcessName -eq "AzCopy" }
                
                # Return process object status
                ($AzCopyPrcessObject -ne $null)
            }
        }
        
        If ($IsAzCopyExecutionRunning) { 
            Write-Output "  AzCopy execution still running..."
            Write-Output "  Waiting for sleep ($SLEEPTIMEOUTLARGE seconds) to be finished"
            Start-Sleep -s $SLEEPTIMEOUTLARGE
        }
		else {
			Write-Output "  AzCopy execution process completed"
		}
    }
	
    # Add checkpoint even If the runbook is suspended by an error, when the job is resumed, 
    # it will resume from the point of the last checkpoint set.
    Checkpoint-Workflow
	 
    Write-Output "Waiting to clean up volumes & turn off the system"
    Start-Sleep -s $SLEEPTIMEOUT
    
    # Disconnect the target portal
    Write-Output "Disconnect the target portal & Unmount the StorSimple volumes"
    $RetryCount = 0
    while ($RetryCount -lt 2)
    {
        $drivesAfterUnMount = InlineScript {
            Invoke-Command -ConnectionUri $Using:VMWinRMUri -Credential $Using:VMCredential -ScriptBlock { 
                param([Int]$SLEEPTIMEOUTSMALL)
                
                    # Disconnect all connected hosts
                    Get-IscsiTarget | Disconnect-IscsiTarget -Confirm:$false -ErrorAction:SilentlyContinue
                    Start-Sleep -s $SLEEPTIMEOUTSMALL
                    
                    # Remove all connected hosts
                    Get-IscsiTargetPortal | Remove-IscsiTargetPortal -Confirm:$false -ErrorAction:SilentlyContinue
                    Start-Sleep -s $SLEEPTIMEOUTSMALL
                    
                    Update-StorageProviderCache
                    Update-HostStorageCache 
                    Start-Sleep -s $SLEEPTIMEOUTSMALL
                    
                    $drives = ((Get-Volume | Where-Object {$_.FileSystem -eq 'NTFS'}).DriveLetter | Sort)
                    
                    # Output of InlineScript
                    ($drives -Join ",")
                    
            } -Argumentlist $Using:SLEEPTIMEOUTSMALL
        }
        
        if ($drivesAfterUnMount -eq $null -or $drivesAfterUnMount.Length -eq 0 ) {
            if ($RetryCount -eq 0) {
                Write-Output "  Retrying for disconnect the target portal & Unmount the StorSimple volume"
            }
            else {
                Write-Output "  Unable to disconnect the target portal & Unmount the StorSimple volume"
            }
            
            # Sleep for 10 seconds before trying again
            Start-Sleep -s $SLEEPTIMEOUTSMALL
            $RetryCount += 1
        }
        else {
            $RetryCount = 2 # To stop the iteration; similar 'break' statement
        }
    }
	
    # Add checkpoint even If the runbook is suspended by an error, when the job is resumed, 
    # it will resume from the point of the last checkpoint set.
    Checkpoint-Workflow

    Write-Output "Initiating cleanup of volumes & volume containers"
    InlineScript
    {
        $TargetDeviceName = $Using:TargetDeviceName
        $VolContainerList = $Using:VolContainerList
        $SLEEPTIMEOUTSMALL = $Using:SLEEPTIMEOUTSMALL
        $SLEEPTIMEOUTLARGE = $Using:SLEEPTIMEOUTLARGE
        
        $VolumeContainers = Get-AzureStorSimpleDeviceVolumeContainer -DeviceName $TargetDeviceName
        if ($VolumeContainers -ne $null)
        {
            Write-Output " Deleting Volumes"
            foreach ($Container in $VolumeContainers) 
            {                
                $Volumes = Get-AzureStorSimpleDeviceVolume -DeviceName $TargetDeviceName -VolumeContainer $Container  
                if ($Volumes -ne $null -and $Container.VolumeCount -gt 0)
                {
                    foreach ($Volume in $Volumes) 
                    {
                        $RetryCount = 0
                        while ($RetryCount -lt 2)
                        {
                            $isSuccessful = $true
                            $id = Set-AzureStorSimpleDeviceVolume -DeviceName $TargetDeviceName -VolumeName $Volume.Name -Online $false -WaitForComplete -ErrorAction:SilentlyContinue
                            if (($id -eq $null) -or ($id[0].TaskStatus -ne "Completed"))
                            {
                                Write-Output "  Volume ($($Volume.Name)) could not be taken offline"
                                $isSuccessful = $false
                            }
                            else
                            {
                                $id = Remove-AzureStorSimpleDeviceVolume -DeviceName $TargetDeviceName -VolumeName $Volume.Name -Force -WaitForComplete -ErrorAction:SilentlyContinue
                                if (($id -eq $null) -or ($id.TaskStatus -ne "Completed"))
                                {
                                    Write-Output "  Volume ($($Volume.Name)) could not be deleted"
                                    $isSuccessful = $false
                                }
                                
                            }
                            if ($isSuccessful) {
                                Write-Output "  Volume ($($Volume.Name)) deleted"
                                break
                            }
                            else
                            {
                                if ($RetryCount -eq 0) {
                                    Write-Output "   Retrying for volumes deletion"
                                }
                                else {
                                    throw "  Unable to delete Volume ($($Volume.Name))"
                                }
                                                 
                                Start-Sleep -s $SLEEPTIMEOUTSMALL
                                $RetryCount += 1   
                            }
                        }
                    }
                }
            }
            
            Start-Sleep -s $Using:SLEEPTIMEOUT
            Write-Output " Deleting Volume Containers"
            foreach ($Container in $VolumeContainers) 
            {
                $RetryCount = 0 
                while ($RetryCount -lt 2)
                {
                    $id = Remove-AzureStorSimpleDeviceVolumeContainer -DeviceName $TargetDeviceName -VolumeContainer $Container -Force -WaitForComplete -ErrorAction:SilentlyContinue
                    if ($id -eq $null -or $id.TaskStatus -ne "Completed")
                    {
                        Write-Output "  Volume Container ($($Container.Name)) could not be deleted"   
                        if ($RetryCount -eq 0) {
                            Write-Output "  Retrying for volume container deletion"
                        }
                        else {
                            Write-Output "  Unable to delete Volume Container ($($Container.Name))"
                        }
                        Start-Sleep -s $SLEEPTIMEOUTSMALL
                        $RetryCount += 1
                    }
                    else
                    {
                        Write-Output "  Volume Container ($($Container.Name)) deleted"
                        break
                    }
                }
            }
        }
    }
	
    # Add checkpoint even If the runbook is suspended by an error, when the job is resumed, 
    # it will resume from the point of the last checkpoint set.
    Checkpoint-Workflow
    
    Write-Output "Attempting to shutdown the SVA & VM"
    foreach ($SystemInfo in $SystemList)
    {
        InlineScript
        {
            $SystemInfo = $Using:SystemInfo
            $Name = $SystemInfo.Name
            $ServiceName = $SystemInfo.ServiceName
            $SystemType = $SystemInfo.Type
            $SLEEPTIMEOUTSMALL = $Using:SLEEPTIMEOUTSMALL
            
            $RetryCount = 0
            while ($RetryCount -lt 2)
            {   
                $Result = Stop-AzureVM -ServiceName $ServiceName -Name $Name -Force
                if ($Result.OperationStatus -eq "Succeeded")
                {
                    Write-Output "  $SystemType ($Name) succcessfully turned off"   
                    break
                }
                else
                {
                    if ($RetryCount -eq 0) {
                        Write-Output "  Retrying for $SystemType ($Name) shutdown"
                    }
                    else {
                        Write-Output "  Unable to stop the $SystemType ($Name)"
                    }
                                     
                    Start-Sleep -s $SLEEPTIMEOUTSMALL
                    $RetryCount += 1   
                }
            }
        }
    }
    
    Write-Output "`n `n Job completed"
}
