$MyWindowsIdentity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$MyWindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($MyWindowsIdentity)
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator
#Check for already admin
If(-Not $MyWindowsPrincipal.IsInRole($AdminRole)) {
    If($MyInvocation.Line -match [RegEx]"$($MyInvocation.MyCommand.Name)['""]?(.*)") {
        $CommandLineAfterScriptFileSpec = $Matches[1]
    }
    else { 
        $CommandLineAfterScriptFileSpec = ""
    }
    $CommandLineAfterScriptFileSpec = $CommandLineAfterScriptFileSpec.Replace('""','~~').Replace('"','""""').Replace('~~', '""""""')
    $objProcess = New-Object System.Diagnostics.ProcessStartInfo "PowerShell"
    $objProcess.Arguments = "-NoExit -Command &'$PSCommandPath'$CommandLineAfterScriptFileSpec"
    $objProcess.Verb = "RunAs"
    $objProcessHandle = [System.Diagnostics.Process]::Start($objProcess)
    Exit
} 
Set-Location $PSScriptRoot

Add-Type -AssemblyName System.Windows.Forms

$certs = Get-ChildItem -Path Cert:\LocalMachine\My 
if($certs.Count -eq 1){
    $cert = $certs[0]
}elseif($certs.Count -eq 0){
   Write-Warning 'No certificates installed on this system.  Please install a certificate into the LocalComputer/Personal/Certificates store.'
   Break 
}else{
    $objForm = New-Object System.Windows.Forms.Form
    $objForm.Text = "Select a Certificate"
    $objForm.Size = New-Object System.Drawing.Size(300, 200)
    $objForm.StartPosition = "CenterScreen"
    $objForm.KeyPreview = $True;
    $objForm.Add_KeyDown({if ($_.KeyCode -eq 'Enter')
        {$objForm.DialogResult = [System.Windows.Forms.DialogResult]::OK;$objForm.Close()}})
    $objForm.Add_KeyDown({if ($_.KeyCode -eq 'Escape')
        {$objForm.Close()}})
    $OKButton = New-Object System.Windows.Forms.Button
    $OKButton.Location = New-Object System.Drawing.Size(75,120)
    $OKButton.Size = New-Object System.Drawing.Size(75,23)
    $OKButton.Text = "OK"
    $OKButton.Add_Click({$objForm.DialogResult = [System.Windows.Forms.DialogResult]::OK;$objForm.Close()})
    $objForm.Controls.Add($OKButton)

    $CancelButton = New-Object System.Windows.Forms.Button
    $CancelButton.Location = New-Object System.Drawing.Size(150,120)
    $CancelButton.Size = New-Object System.Drawing.Size(75,23)
    $CancelButton.Text = "Cancel"
    $CancelButton.Add_Click({$objForm.Close()})
    $objForm.Controls.Add($CancelButton)

    $objLabel = New-Object System.Windows.Forms.Label
    $objLabel.Location = New-Object System.Drawing.Size(10,20)
    $objLabel.Size = New-Object System.Drawing.Size(280,20)
    $objLabel.Text = 'Please select a certificate:'
    $objForm.Controls.Add($objLabel)

    $objListBox = New-Object System.Windows.Forms.ListBox
    $objListBox.Location = New-Object System.Drawing.Size(10,40)
    $objListBox.Size = New-Object System.Drawing.Size(260,20)
    $objListBox.Height = 80
    
    for($i = 0; $i -lt $certs.count; $i++){
        $subject = $certs[$i].Subject
        [void] $objListBox.Items.Add($subject)
    }

    $objForm.Controls.Add($objListBox)

    $objForm.TopMost = $True

    $objForm.Add_Shown({$objForm.Activate()})
    $res = $objForm.ShowDialog()
    
    if($res -eq [System.Windows.Forms.DialogResult]::OK -and $objListBox.SelectedItem){
        $cert = $certs[$objListBox.SelectedIndex]
    }else{
        Write-Warning 'Please select a certificate'
        Break
    }
}

<# Get NPS Users Group #>
$group = Read-Host -Prompt 'Input name of existing Active Directory Security Group whose members will be able to access this application'
$group = $group.Trim()
if($group.Length -eq 0){
    Write-Warning 'No name input.  Aborting install.'
    Break;
}
$filter = "(&(objectCategory=Group)(Name=$group))"
$objDomain = New-Object System.DirectoryServices.DirectoryEntry
$objSearcher = New-Object System.DirectoryServices.DirectorySearcher
$objSearcher.SearchRoot = $objDomain
$objSearcher.Filter = $filter
$objSearcher.SearchScope = "Subtree"
$objSearcher.PropertiesToLoad.Add('name') | Out-Null
$results = $objSearcher.FindOne()
if(-not ($results)){
    Write-Warning "$group is not a valid group.  Aborting install."
    Break
}

Do { $port = Read-host 'Server port (Valid range 0-65536) [default value 443]'}
while ($port -ne "" -and ($port -notmatch "^[\d\.]+$" -or $port -lt 0 -or $port -gt 65536))
if($port -eq ""){
    $port = 443
}

<# Get NPS Service Account #>
$creds = Get-Credential -Message 'Input NPS Service Account credentials (must be local admin on NPS servers) in domain\name format, e.g. NAE\nps.gui.svc'
if(-NOT $creds){
    Write-Warning 'User cancelled install.  Aborting install.'
    Break
}
$credCheck = New-Object System.DirectoryServices.DirectoryEntry("",$creds.UserName,$creds.GetNetworkCredential().Password)
if ($credCheck.name -eq $null)
{
    Write-Warning "Authentication failed - please verify the service account username and password."
    Break
}

$deployUserName = $creds.UserName
$deployUserPassword = $creds.GetNetworkCredential().Password

<# Get NPS Install Directory #>
$FolderBrowser = New-Object System.Windows.Forms.OpenFileDialog -Property @{
    Filter = 'foldersOnly|*.none'
    CheckfileExists = $False
    CheckPathExists = $False
    InitialDirectory = "C:\"
    Title = "Select Target Installation Folder"
    FileName = "NPS GUI"

}
$res = $FolderBrowser.ShowDialog()
if($res -ne [System.Windows.Forms.DialogResult]::OK){
    Write-Host 'User cancelled install.  Aborting.'
    Break
}
$folder = [System.IO.Path]::GetDirectoryName($FolderBrowser.FileName)
if($folder -notlike '*NPS\GUI'){
    $deployDir = Join-Path $folder 'NPS'
    $deployDir = Join-Path $deployDir 'GUI'
}

$computerarray = @()
do {
    $input = (Read-Host "Please input an NPS backend server FQDN (nps.nae.ds.army.mil) or IP address (192.168.1.1) [leave empty to finish]")
    if ($input -ne '') {$computerarray += $input.Trim()}
}
until ($input -eq '')

if($computerarray.Count -eq 0){
    Write-Warning 'You need at least one backend NPS server.  Aborting install.'
    Break
}
$nps_string = $computerarray -join ','

<# Install required Windows Features #>
Write-Host "Installing required Windows features.  Includes IIS, .NET 4.5, and ASP.NET."
$features  = @("web-server","web-webserver", "web-common-http","web-static-content",
'web-default-doc','web-dir-browsing','web-http-redirect','web-http-errors','web-health',
'web-http-logging','web-log-libraries','web-http-tracing','web-performance','web-stat-compression',
'web-filtering','web-app-dev','web-net-ext45','web-asp-net45','web-isapi-ext','web-isapi-filter',
'web-client-auth','web-mgmt-tools','web-mgmt-console','NET-Framework-45-ASPNET','NET-Framework-45-Features')
Install-WindowsFeature -Name $features -IncludeManagementTools -Confirm


<# Create install directory and set permissions #>
try{
    if(Test-Path -path $deployDir){
        Remove-Item $deployDir -Recurse -ErrorAction Stop 
        sleep -Seconds 1
    }
    $dir = New-Item -ItemType directory -Path $deployDir -ErrorAction Stop
}
catch 
{
    Write-Warning "Failed to create directory $deployDir, do you have permissions to do so?"
    Write-Error $_.Exception.Message
    Break
}
$acl = Get-Acl $dir

#Set the Service Account as the owner
$acl.SetOwner([System.Security.Principal.NTAccount]$env:USERNAME)

#Break inheritance
$acl.SetAccessRuleProtection($True, $False)
$inheritance = [System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]::None
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($group, "ReadAndExecute", $inheritance, $propagation, "Allow")
$acl.SetAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($creds.UserName, "ReadAndExecute", $inheritance, $propagation, "Allow")
$acl.SetAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", $inheritance, $propagation, "Allow")
$acl.AddAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule($env:USERNAME, "FullControl", $inheritance, $propagation, "Allow")
$acl.AddAccessRule($rule)
$rule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", $inheritance, $propagation, "Allow")
$acl.AddAccessRule($rule)
Set-Acl -Path $dir -AclObject $acl

<# Copy install files into the deploy directory #>
$install_files = '.\Install_Files\*'

if(Test-Path $install_files){
    Copy-Item -Path $install_files -Destination $deployDir -Recurse -ErrorAction Stop
}else{
    Write-Error $_.Exception.Message
    Write-Warning "Failed to install files '$install_files'.  Aborting install."
    Break
}
 
   
<# Setup IIS Site and App pool #>
Import-Module WebAdministration
Write-Host "Setting up IIS site and app pool"
$name = "NPS_MAB_Editor"
$app_pool_path = Join-Path IIS:\AppPools\ $name
$site_path = Join-Path IIS:\Sites\ $name
if(Test-Path $app_pool_path)
{
	Remove-WebAppPool $name
}
$pool = New-Item $app_pool_path

$pool.processModel.identityType = 3
$pool.processModel.userName = $deployUserName
$pool.processModel.password = $deployUserPassword
$pool | set-item

if(Test-Path $site_path)
{
    Remove-WebSite $name
}
$site = New-Website -name $name -PhysicalPath $deployDir -ApplicationPool $name -Ssl -Port $port
$guid = [guid]::NewGuid()
$certCommand = "http delete sslcert ipport=0.0.0.0:$port"
$certCommand | netsh
$certCommand = "http add sslcert ipport=0.0.0.0:$port certhash=$($cert.Thumbprint) appid={$guid} dsmapperusage=enable clientcertnegotiation=enable"
$certCommand | netsh

Start-Sleep -Seconds 1
[System.Reflection.Assembly]::LoadWithPartialName('Microsoft.Web.Administration') 
$oIIS = New-Object Microsoft.Web.Administration.ServerManager
$conf = $oIIS.GetApplicationHostConfiguration()
$conf.RootSectionGroup.SectionGroups['system.webserver'].SectionGroups['security'].Sections['access'].OverrideModeDefault="Allow"
$conf.RootSectionGroup.SectionGroups['system.webserver'].SectionGroups['security'].SectionGroups['authentication'].Sections['anonymousAuthentication'].OverrideModeDefault="Allow"
$conf.RootSectionGroup.SectionGroups['system.webserver'].SectionGroups['security'].SectionGroups['authentication'].Sections['clientCertificateMappingAuthentication'].OverrideModeDefault="Allow"
$oIIS.CommitChanges()
Start-Sleep -Seconds 1
Set-WebConfigurationProperty -filter /system.webServer/security/authentication/anonymousAuthentication -name enabled -value false -PSPath $site_path 
Set-WebConfigurationProperty -filter /system.webServer/security/authentication/clientCertificateMappingAuthentication -name enabled -value true 
Set-WebConfigurationProperty -Filter /system.webServer/security/access -name sslFlags -value "Ssl,SslNegotiateCert,SslRequireCert" -PSPath $site_path 
Add-WebConfigurationProperty -filter /appSettings -name "." -value @{key='nps_servers';value=$nps_string} -pspath $site_path
Add-WebConfigurationProperty -Filter /appSettings -name "." -value @{key=($env:UserDomain + "\" + $creds.UserName);value=".*"} -PSPath $site_path

Write-Host 'Finished Installation.'
$site.Start()
if($site.state -eq 'Started' -or $site.state -eq 'Starting'){
    $myFQDN=(Get-WmiObject win32_computersystem).DNSHostName+"."+(Get-WmiObject win32_computersystem).Domain
    if($port -ne 443){
        $myFQDN += ":$port"
    }
    Write-Host "Application now available at https://$myFQDN/"
}else{
    Write-Warning "Install completed but was unable to start the application.  Is there already a site running on port $($port)?"
}
