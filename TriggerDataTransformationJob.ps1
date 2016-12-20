<#
.DESCRIPTION
    This runbook triggers the Data Transformation Job. 
    This runbook depends on C# dlls which handles the Data transformation calls.  
     
.ASSETS     
    SubscriptionId: The Subscription Id of the Azure. 
    TenantId: The Tenant Id (guid) of the Azure Active Directory (AAD) tenant where the service principal resides.
    ClientId: The Client Id of AAD app which has permissions to KeyVault
    ActiveDirectoryKey: Client Secret of AAD app which has permissions to KeyVault
    ResourceGroupName: The Resource group name of the DMS
    DataManagerName: The name of the DataManager Resource within the specified resource group.
    JobDefinitionName: The name of the Job definition.

.NOTES:

#>

workflow CallDMSJob
{
    param
    (
        [Parameter(Mandatory=$true)]
        [string]$SubscriptionId = "2136cf2e-684f-487b-9fc4-0accc9c0166e",

        [Parameter(Mandatory=$true)]
        [string]$TenantId = "72f988bf-86f1-41af-91ab-2d7cd011db47",

        [Parameter(Mandatory=$true)]
        [string]$ClientId = "903c2dfe-aa8a-4f7c-b9bb-3f0c35d8af5a",

        [Parameter(Mandator=$true)]
        [string]$ActiveDirectoryKey = "StorSim1",

        [Parameter(Mandator=$true)]
        [string]$ResourceGroupName = "dmsrg1",

        [Parameter(Mandator=$true)]
        [string]$DataManagerName = "haritestresource",

        [Parameter(Mandator=$true)]
        [string]$JobDefinitionName = "jobDefMedia3"
    ) 
    
    Write-Output "Job initiated"
    #ls C:\Modules\User\DataTransformationApp
    
    $jobParams = @{
        SubscriptionId = $SubscriptionId;
        TenantId = $TenantId;
        ApplicationId = $ClientId;
        ActiveDirectoryKey = $ActiveDirectoryKey;
        ResourceGroupName = $ResourceGroupName;
        ResourceName = $DataManagerName;
        JobDefinitionName = $JobDefinitionName
    }

    InlineScript {
        $jobParams = $Using:jobParams

        # Load all dependent dlls
        $data = [Reflection.Assembly]::LoadFile("C:\Modules\User\DataTransformationApp\Newtonsoft.Json.dll")
        $data = [Reflection.Assembly]::LoadFile("C:\Modules\User\DataTransformationApp\DataTransformationApp.dll")
        $data = [Reflection.Assembly]::LoadFile("C:\Modules\User\DataTransformationApp\Microsoft.Rest.ClientRuntime.dll")
        $data = [Reflection.Assembly]::LoadFile("C:\Modules\User\DataTransformationApp\Microsoft.Rest.ClientRuntime.Azure.Authentication.dll")
        $data = [Reflection.Assembly]::LoadFile("C:\Modules\User\DataTransformationApp\Microsoft.IdentityModel.Clients.ActiveDirectory.dll") 

        # Trigger Job definition
        [DataTransformationApp.DataTransformationApp]::RunJob($jobParams)
    }
}
