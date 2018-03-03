using System;
using System.Linq;
using System.Collections.Generic;
using System.Management.Automation;
using System.Text;
using System.Web.Script.Serialization;
using System.Configuration;
using System.Web;
using System.Security.Principal;
using System.Text.RegularExpressions;
using System.Collections;

namespace NPS_Web_App
{

    public partial class _default : System.Web.UI.Page
    {

        List<string> Policies;

        public string GetJSONPolicyMacs {
            get {
                Dictionary<string, ArrayList> dict = new Dictionary<string, ArrayList>();
                foreach (var pair in ExecuteCode<Hashtable>("Get-DictionaryPolicies -PolicyNames $arg0", false, (object)Policies.ToArray()))
                {
                    foreach (var p in pair)
                    {
                        var entry = (DictionaryEntry)p;
                        if (entry.Value is PSObject)
                            dict.Add((string)entry.Key, (((PSObject)entry.Value).BaseObject as ArrayList));
                        else if (entry.Value is string)
                        {
                            dict.Add((string)entry.Key, new ArrayList() { (string)entry.Value });
                        }
                        else if (entry.Value is null)
                        {
                            dict.Add((string)entry.Key, new ArrayList());
                        }
                    }
                }
                return new JavaScriptSerializer().Serialize(dict);
            }
        }

        protected override void OnLoad(EventArgs e)
        {
            base.OnLoad(e);
            Policies = GetPolicies();
            if (!IsPostBack)
            {
                Response.AppendToLog($"{Request.LogonUserIdentity.Name} logged into NPS Editor from {Request.UserHostAddress}");
                //GetPolicies(PolicyList, null);
                //ChangePolicy(PolicyList, null);
            }
        }

        protected void DeleteMAC(object sender, EventArgs e)
        {
            var policy = Server.HtmlDecode(Request.Form["PolicyList"]);
            if (!Policies.Contains(policy))
            {
                throw new Exception($"{HttpContext.Current.User.Identity.Name} does not have permissions for {policy}.");
            }
            List<string> values = new List<string>();
            foreach (string val in Request.Form.GetValues("MACBox"))
            {
                values.Add(Server.HtmlDecode(val));
            }
            if (values.Count > 0)
            {
                Response.AppendToLog($"{Request.LogonUserIdentity.Name} NPS Editor deleted MAC addresses {String.Join(",", values)} from policy {policy}");
                ExecuteCode<string>("Remove-NPSPolicyMACAddress -MACAddress $arg0 -PolicyName $arg1", true, values.ToArray(), policy);
            }
        }

        protected void AddMAC(object sender, EventArgs e)
        {
            var policy = Server.HtmlDecode(Request.Form["PolicyList"]);
            if (!Policies.Contains(policy))
            {
                throw new Exception($"{HttpContext.Current.User.Identity.Name} does not have permissions for {policy}.");
            }
            var macs = MACInput.Text.Split(new char[] { '\n' }, StringSplitOptions.RemoveEmptyEntries);
            for (int i = 0; i < macs.Length; ++i)
            {
                macs[i] = Server.HtmlDecode(macs[i].Trim());
            }
            if (macs.Length > 0)
            {
                Response.AppendToLog($"{Request.LogonUserIdentity.Name} NPS Editor added MAC addresses {String.Join(",", macs)} to policy {policy}");
                ExecuteCode<string>("Add-NPSPolicyMACAddress -MACAddress $arg0 -PolicyName $arg1", true, macs, policy);
                MACInput.Text = "";
            }
        }

        protected List<string> GetMACAddresses(string policy)
        {
            if (!Policies.Contains(policy))
            {
                throw new Exception($"{HttpContext.Current.User.Identity.Name} does not have permissions for {policy}.");
            }
            var macs = ExecuteCode<string>($"Get-NPSPolicyMACAddress -PolicyName $arg0", false, policy);
            if (macs.Count == 0)
            {
                macs.Add("NO MAC ADDRESSES FOUND");
            }
            macs.Sort(delegate (string x, string y)
            {
                x.Replace("-", "");
                x.Replace(".", "");
                y.Replace("-", "");
                y.Replace(".", "");
                return x.CompareTo(y);
            });
            return macs;
        }

        private List<string> GetUserGroups()
        {
            var groups = new List<string>();

            foreach (IdentityReference group in HttpContext.Current.Request.LogonUserIdentity.Groups)
            {
                groups.Add(group.Translate(typeof(NTAccount)).ToString());
            }
            groups.Add(HttpContext.Current.Request.LogonUserIdentity.User.Translate(typeof(NTAccount)).ToString());
            throw new Exception(groups.Last());
            return groups;
        }

        protected List<string> GetPolicies()
        {
            //Get all of the policies
            var policies = ExecuteCode<string>("Get-NPSPolicies", false);

            //Get user's groups
            var groups = GetUserGroups();

            //Check each group to see if it has permissions associated
            var fullPermissionList = new List<string>();
            foreach (var group in groups)
            {
                foreach (var key in ConfigurationManager.AppSettings.AllKeys)
                {
                    if (string.Equals(key, group, StringComparison.InvariantCultureIgnoreCase))
                    {
                        var permissions = ConfigurationManager.AppSettings[key];
                        var permissionList = SplitString(permissions);
                        fullPermissionList.AddRange(permissionList);
                    }
                }
            }

            //Build a new list of policies that match the permissions
            var newPolicies = new List<string>();
            foreach (var groupPolicyRegexString in fullPermissionList)
            {
                Regex r = new Regex("^" + groupPolicyRegexString + "$", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);
                foreach (var policy in policies)
                {
                    if (r.IsMatch(policy))
                    {
                        newPolicies.Add(policy);
                    }
                }
            }
            policies = newPolicies;
            if (policies.Count == 0)
            {
                throw new Exception($"User {HttpContext.Current.User.Identity.Name} does not have permissions to view any policies.");
            }
            return policies;
        }

        private List<string> SplitString(string s)
        {
            var returnList = new List<string>();
            if (s != null && s.Length > 0)
            {
                if (s.Contains(","))
                {
                    returnList.AddRange(s.Split(',').Select(x => x.Trim()));
                }
                else
                {
                    returnList.Add(s.Trim());
                }
            }
            return returnList;
        }

        protected List<T> ExecuteCode<T>(string command, bool sync, params object[] args) where T : class
        {
            //Get the list of NPS Backend servers
            var serverString = ConfigurationManager.AppSettings["nps_servers"];
            var servers = SplitString(serverString);
            if (servers.Count == 0)
            {
                throw new Exception("Failed to find any NPS Servers.  Is the nps_servers configuration property set?");
            }

            // Initialize PowerShell engine
            var shell = PowerShell.Create();
            var blockText = new StringBuilder();
            if (args.Length > 0)
            {
                blockText.AppendLine("param(");
            }
            for (int i = 0; i < args.Length; ++i)
            {
                blockText.Append($"$arg{i}");
                if (i < args.Length - 1) blockText.Append(",");
            }
            if (args.Length > 0)
            {
                blockText.AppendLine(")");
            }
            blockText.AppendLine(NPSFunctions);
            blockText.AppendLine(command);
            var block = ScriptBlock.Create(blockText.ToString());
            shell.AddCommand("Invoke-Command");
            shell.AddParameter("ComputerName", servers[0]);
            shell.AddParameter("ScriptBlock", block);
            if (args.Length > 0)
            {
                shell.AddParameter("ArgumentList", args);
            }

            // Execute the script
            var results = shell.Invoke();

            foreach (var error in shell.Streams.Error)
            {
                throw error.Exception;
            }

            //Collect the results
            var resultOutput = new List<T>();
            foreach (var psObject in results)
            {
                resultOutput.Add(psObject.BaseObject as T);
            }

            if (servers.Count > 1 && sync)
            {
                shell = PowerShell.Create();
                shell.AddScript($"{NPSFunctions}\nSync-NPSServers {servers[0]} {String.Join(",", servers.Skip(1))}");
                results = shell.Invoke();
                if (results.Count > 0)
                {
                    var output = new List<string>();
                    foreach (var psObject in results)
                    {
                        output.Add(psObject.BaseObject.ToString());
                    }
                    throw new Exception(string.Join(", ", output));
                }
            }

            return resultOutput;
        }

        private string NPSFunctions = @"
function Format-MACAddress {
    param(
        [string[]]$MACAddress
    )
    process {
        $macs = @()
        
        foreach($mac in $MACAddress){
            if($mac -match '^[a-fA-F0-9]{12}$'){
                $out = $mac.Substring(0,2) + ""-"" + $mac.Substring(2,2) + ""-"" + $mac.Substring(4,2) + ""-"" + $mac.Substring(6,2) + ""-"" + $mac.Substring(8,2) + ""-"" + $mac.Substring(10,2)
                $macs += $out.ToLower()
            } elseif($mac -match '^[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}$') {
                $macs += $mac.ToLower()
            } elseif($mac -match '^[a-fA-F0-9]{6}\.\*$') {
                $out = $mac.Substring(0, 2) + ""-"" + $mac.Substring(2, 2) + ""-"" + $mac.Substring(4, 2) + ""-.*""
                $macs += $out.ToLower()
            } elseif($mac -match '^[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-[a-fA-F0-9]{2}-\.\*$') {
                $macs += $mac.ToLower()
            } elseif($mac -match '^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:\.\*$') {
                $macs += $mac.ToLower().Replace(':','-')
            } elseif($mac -match '^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}$') {
                $macs += $mac.ToLower().Replace(':','-')
            } elseif($mac -match '^[a-fA-F0-9]{4}\.[a-fA-F0-9]{2}\.\*$') {
                $out = $mac.Substring(0, 2) + ""-"" + $mac.Substring(2, 2) + ""-"" + $mac.Substring(5, 2) + ""-.*""
                $macs += $out.ToLower()
            } elseif($mac -match '^[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}\.[a-fA-F0-9]{4}$') {
                $out = $mac.Substring(0, 2) + ""-"" + $mac.Substring(2, 2) + ""-"" + $mac.Substring(5, 2) + ""-"" + $mac.Substring(7, 2) + ""-"" + $mac.Substring(10, 2) + ""-"" + $mac.Substring(12, 2)
                $macs += $out.ToLower()
            }  else {
                if($mac -ne '' -and $mac -ne 0)
                {
                    write-warning ""'$mac' is not in the correct format '0F0F0F0F0F0F', '0F-0F-0F-0F-0F-0F','0F:0F:0F:0F:0F:0F', '0F0F.0F0F.0F0F', '000000.*', '00-00-00-.*', '00:00:00:.*', or '0000.00.*' and will not be included"" 
                }
            }
        }
        
        return $macs
    }
}

function Get-NPSPolicyMACNode {
    param(
        [xml]$xml,
        [string]$PolicyName
    )

    process {
        
        $policy = $xml.Root.Children.Microsoft_Internet_Authentication_Service.Children.Proxy_Policies.Children.ChildNodes | ? { $_.name -eq ""$PolicyName"" }

        if ($policy -ne $null) {
            if($policy.name.Count -eq 1) {
                $MACList = $policy.Properties.msNPConstraint | ? { $_.'#text' -like 'MATCH(""Calling-Station-Id*' }

                if($MACList -ne $null) {
                    if($MACList.'#text'.Count -eq 1) {
                        return $MACList                            
                    } else {
                        Throw ""Connection Request Policy '$PolicyName' has more than one constraint for Calling-Station-Id please remove one and try again""
                    }
                } else {
                    Throw ""Connection Request Policy '$PolicyName' does not contain any constraints for Calling-Station-Id""
                }
                
            } else {
                Throw ""More than one policy name containing '$PolicyName'""
            }
        } else {
            Throw ""No Connection Request Policies have the name '$PolicyName'""
        }
    }

}

<#
.SYNOPSIS
Adds a MAC address to a specified NPS connection request policy.The function will eliminate any
duplicates that are being added.
.PARAMETER MACAddress
The MAC address(es) to add to the NPS connection request policy.
.PARAMETER PolicyName
The NPS connection request policy name.  This policy must have a condition for Calling-Station-Id.
.EXAMPLE
# This example appends the MAC addresses to the policy.

$macs = '000000000000','000000000001'
Add-NPSPolicyMACAddress -MACAddress $macs -PolicyName Policy1
.EXAMPLE
# This example overwrites the existing MAC addresses and only includes those specified in the $macs variable.

$macs = '000000000000','000000000001'
Add-NPSPolicyMACAddress -MACAddress $macs -PolicyName Policy1 -Overwrite
.EXAMPLE
$macs = Get - Content macList.txt
Add-NPSPolicyMACAddress -MACAddress $macs -PolicyName Policy1
#>
function Add-NPSPolicyMACAddress {
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)]
        [string[]]$MACAddress,
        [Parameter(Mandatory =$true, ValueFromPipeline =$true, ValueFromPipelinebyPropertyName =$true)]
[string]$PolicyName,
        [switch]$Overwrite
    )

    begin {
        $filePath = [System.IO.Path]::GetTempPath() + [Guid]::NewGuid().ToString() + "".xml""        
    }

    process {
        $MACAddress = Format-MACAddress $MACAddress | Group-Object | % Name
        
        if($MACAddress -eq $null -and $Overwrite -eq $false)
        {
            Throw ""None of the supplied MAC addresses are in the correct format""
        }

        Export-NpsConfiguration -Path $filePath
        [xml]$x = Get-Content -Path $filePath -Raw

        $MACList = Get-NPSPolicyMACNode $x $PolicyName 

        $ExistingMACs = Get-NPSPolicyMACAddress $PolicyName | Group-Object | % Name

        if($ExistingMACs -eq $null){
            $Overwrite = $true
        }

        $MACAddressString = New-Object System.Text.StringBuilder
        $MACAddressString.Append('MATCH(""Calling-Station-Id=') | Out-Null

        if($Overwrite -eq $false){        
            $MACAddress += $ExistingMACs  
        } 

        if($MACAddress -eq $null -and $Overwrite -eq $true) {
            $MACAddressString.Append(""^$"") | Out - Null
        }
        else
        {
            $MACAddress = $MACAddress | Group-Object | % Name
            for($i = 0; $i -lt $MACAddress.Count;$i++){
                if($i -eq 0)
                {
                    $MACAddressString.Append(""^"" + $MACAddress[0] + ""$"") | Out-Null
                }
                else
                {
                    $MACAddressString.Append(""|^"" + $MACAddress[$i] + ""$"") | Out-Null
                }
            }
        }
        
        $MACList.'#text' = $MACAddressString.ToString() + $matchString +'"")'
        $MACList.OwnerDocument.OuterXml | Out-File $filePath
        Import-NpsConfiguration -Path $filePath
    }

    end {
        if(Test-Path $filePath) {
            Remove-Item $filePath
        }
    }
}

<#
.SYNOPSIS
Removes a MAC address(es) from a specified NPS connection request policy.
.PARAMETER MACAddress
The MAC address(es) to add to the NPS connection request policy.
.PARAMETER PolicyName
The NPS connection request policy name.This policy must have a condition for Calling-Station-Id.
.EXAMPLE
This example appends the MAC addresses to the policy.

$macs = '000000000000','000000000001'
Remove-NPSPolicyMACAddress -MACAddress $macs -PolicyName Policy1
.EXAMPLE
$macs = Get-Content macList.txt
Remove-NPSPolicyMACAddress -MACAddress $macs -PolicyName Policy1
#>
function Remove-NPSPolicyMACAddress {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)]
        [string[]]$MACAddress,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)]
        [string]$PolicyName
    )

    begin {
        $filePath = [System.IO.Path]::GetTempPath() + [Guid]::NewGuid().ToString() + "".xml""        
    }

    process {
        $MACAddress = Format-MACAddress $MACAddress | Group-Object | % Name
        if($MACAddress -eq $null)
        {
            Throw ""None of the supplied MAC addresses are in the correct format""
        }
        Export-NpsConfiguration -Path $filePath
        [xml]$x = Get-Content -Path $filePath -Raw
        
        $MACList = Get-NPSPolicyMACNode $x $PolicyName

        $ExistingMACs = Get-NPSPolicyMACAddress $PolicyName | Group-Object | % Name
        
        $MACAddressString = New-Object System.Text.StringBuilder
        $MACAddressString.Append('MATCH(""Calling-Station-Id=') | Out-Null

        foreach($mac in $MACAddress)
        {
            [array]$ExistingMACs = $ExistingMACs | ? { $_ -ne $mac }
        }

        for($i = 0; $i -lt $ExistingMACs.Count;$i++){
            if($i -eq 0)
            {
                $MACAddressString.Append(""^"" + $ExistingMACs[0] + ""$"") | Out-Null
            }
            else 
            {
                $MACAddressString.Append(""|^"" + $ExistingMACs[$i] + ""$"") | Out-Null
            }
        }

        if($ExistingMACs.Count -eq 0){
            $MACAddressString.Append(""^$"") | Out-Null
        }

        $MACList.'#text' = $MACAddressString.ToString() + $matchString +'"")'    
        $MACList.OwnerDocument.OuterXml | Out-File $filePath

        Import-NpsConfiguration -Path $filePath       
    }

    end {
        if(Test-Path $filePath) {
            Remove-Item $filePath
        }
    }
}

<#
.SYNOPSIS
Verifies that a MAC address is in a specified NPS connection request policy.  
.PARAMETER MACAddress
The MAC address to verify.
.PARAMETER PolicyName
The NPS connection request policy name.  This policy must have a condition for Calling-Station-Id.
.EXAMPLE
Confirm-NPSPolicyMACAddress '000000000000' Policy1
#>
function Confirm-NPSPolicyMACAddress {
        param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)]
        [string]$MACAddress,
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)]
        [string]$PolicyName
    )

    begin {
        $filePath = [System.IO.Path]::GetTempPath() + [Guid]::NewGuid().ToString() + "".xml""
        $MACAddress = Format-MACAddress $MACAddress
    }

    process {
        Export-NpsConfiguration -Path $filePath
        [xml]$x = Get-Content -Path $filePath -Raw

        $MACList = Get-NPSPolicyMACNode $x $PolicyName

        if(([string]$MACList.'#text').IndexOf($MACAddress) -gt -1) {
            return $true
        } else {
            return $false                           
        } 

    }

    end {
        if(Test-Path $filePath) {
            Remove-Item $filePath
        }
    }
}

<#
.SYNOPSIS
Gets an array of MAC addresses from a specified NPS connection request policy.  
.PARAMETER PolicyName
The NPS connection request policy name.  This policy must have a condition for Calling-Station-Id.
.EXAMPLE
Get-NPSPolicyMACAddress Policy1
#>
function Get-NPSPolicyMACAddress {
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)]
        [string]$PolicyName
    )

    begin {
        $filePath = [System.IO.Path]::GetTempPath() + [Guid]::NewGuid().ToString() + "".xml""
    }

    process {
        Export-NpsConfiguration -Path $filePath
        [xml]$x = Get-Content -Path $filePath -Raw

        $MACList = Get-NPSPolicyMACNode $x $PolicyName

        $MACs = ([string]$MACList.'#text').Replace('MATCH(""Calling-Station-Id=',"""").Replace('"")',"""").Replace(""^"","""").Replace(""$"","""").Split(""|"")
        $macs = Format-MACAddress $macs
        return $MACs
    }

    end {
        if(Test-Path $filePath) {
            Remove-Item $filePath
        }
    }
}

function Get-DictionaryPolicies {
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline=$true,ValueFromPipelinebyPropertyName=$true)]
        [string[]]$PolicyNames
    )

    begin {
        $filePath = [System.IO.Path]::GetTempPath() + [Guid]::NewGuid().ToString() + "".xml""
    }

    process {
        Export-NpsConfiguration -Path $filePath
        [xml]$x = Get-Content -Path $filePath -Raw

        $macHash = @{}
        foreach($policy in $PolicyNames)
        {
            $MACList = Get-NPSPolicyMACNode $x $policy

            $MACs = ([string]$MACList.'#text').Replace('MATCH(""Calling-Station-Id=',"""").Replace('"")',"""").Replace(""^"","""").Replace(""$"","""").Split(""|"")
            $MACs = Format-MACAddress $MACs
            $macHash.Add($policy, $MACs)
        }
        return $macHash
    }

    end {
        if(Test-Path $filePath) {
            Remove-Item $filePath
        }
    }
}

<#
.SYNOPSIS
Synchronizes NPS server configurations between two or more servers from a single source server configuration.  
.PARAMETER SourceServer
The NPS server that is the master configuration.
.PARAMETER DestinationServer
The NPS server(s) that will be configured the same as the $SourceServer.
.EXAMPLE
This example syncs server2 with server1's configuration.

Sync-NPSServers ""server1"" ""server2""
.EXAMPLE

Sync-NPSServers ""server1"" ""server2"",""server3""
#>
function Sync-NPSServers {
    param(
        [string]
        $SourceServer,
        [string[]]
        $DestinationServer
    )
    process {
        Invoke-Command -ComputerName $sourceServer -ScriptBlock {
            Invoke-Expression $('netsh nps export filename=""c:\config.xml"" exportPSK=YES' ) | Out-Null
        }
        foreach($server in $destinationServer)
        {
            $source = '\\' + $sourceServer + '\c$\config.xml'
            $dest = '\\' + $server + '\c$'
            Copy-Item $source $dest -ErrorAction stop -ErrorVariable ProcessError
            if($ProcessError){
                throw ""Failed to copy file from $source to $dest due to $ProcessError""
            }
            if(Test-Path $($dest+'\config.xml'))
            {
                Invoke-Command -ComputerName $server -ScriptBlock {
                    Invoke-Expression $('netsh nps import filename=""c:\config.xml""' ) | Out-Null
                }
                Remove-Item $($dest+'\config.xml')
            }
            else
            {
                throw ""Unable to copy file to destination server. Sync failed.""
            }
        }
    }
    end {
        Remove-Item $source
    }
}
function Get-NPSPolicies {
    begin {
        $filePath = [System.IO.Path]::GetTempPath() + [Guid]::NewGuid().ToString() + "".xml""
    }
    process {
        Export-NpsConfiguration -Path $filePath
        [xml]$x = Get-Content -Path $filePath -Raw
        $policy = $x.Root.Children.Microsoft_Internet_Authentication_Service.Children.Proxy_Policies.Children.ChildNodes | where-object {$_.Properties.msNPConstraint.'#text' -like 'MATCH(""Calling-Station-Id*' }
        $policyNames = $policy | select -ExpandProperty Name
        return $policyNames
    }
    end {
        if(Test-Path $filePath) {
            Remove-Item $filePath
        }
    }
}
";
    }
}