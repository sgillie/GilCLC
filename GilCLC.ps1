# C:\Workbox\repos\GilCLC\GilCLC.ps1 Build: 120 2017-03-04T12:10:01 Copyright CLC Stephen Gillie 
# Update Path: 
# Build : Update Notes
# 116 : 763 :  Param_    $NoClipboard   _; #end Param
# 117 : 786 : Function Convert_ZDTC _     Param_     $TicketNumber    _; #end Param    _; #end Convert_ZDTC
# 118 : 789 : $g = Get_ZenDeskTicketComment 1353628 $r = $g[1].body _split "`n" _$r | Select_String 'Hello'_.LineNumber _$r | Select_String 'Thanks'_.LineNumber $r[__$r | Select_String 'Hello'_.LineNumber+1_..__$r | Select_String 'Thanks'_.LineNumber_3_]
# 119 : 246 : if _$NoConvert_ _  #a _; # end if NoConvert
# 120 : 239 :  Param_    $NoConvert   _; #end Param

#$GilCLC = (Get-Module GilCLC).path
$GilCLCVersion = ([int](gc $GilCLC)[0].split(" ")[3])
Write-Host -f green "GilCLC.ps1 Build: $GilCLCVersion"

# [<]{7}[ ][H][E][A][D].*\r\n.*\r\n[=]{7}
# [>>>>>>>].*\r

Function Get-MySharona([Scriptblock]$Param, [Scriptblock]$Callback) {
<#
.SYNOPSIS
	Demonstration of callbacks.
.DESCRIPTION
	 Author   : Stephen Gillie
.PARAMETER Param
	 Parameter to test.
.PARAMETER Callback
	 Scriptblock to invoke if the Param tests True.
.EXAMPLE
	 Get-MySharona (Test-Connection ctl.io) {write-host "Test successful."}
.INPUTS
	[Scriptblock]
	[Scriptblock]
.OUTPUTS
#>
	if($param) {
		& $callback
	}
}; #end Get-MySharona

#region Juniper

Function Get-SRXLogs {
<#
.SYNOPSIS
	Looks up a server in Control, then reviews SRX logs for 
.DESCRIPTION
	 Author   : Stephen Gillie
.PARAMETER 
	 Author   : Stephen Gillie
.PARAMETER 
.PARAMETER 
.PARAMETER 
.PARAMETER 
.EXAMPLE
	 Get-MySharona (Test-Connection ctl.io) {write-host "Test successful."}
.INPUTS
	[Scriptblock]
	[Scriptblock]
.OUTPUTS
#>
	Param(
		[string]$ServerName,
		[string]$Datacenter = $ServerName.Substring(0,3),
		$Server = $(try {Find-ControlServer $ServerName} catch{}),
		$PublicIP = $($Server.Details.IPAddresses.Public),
		$InternalIP = $($Server.Details.IPAddresses.Internal),
		[int]$Last = 100
	); #end Param
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }

	"$(get-date (get-date).ToUniversalTime() -f "MMM dd HH:mm:ss") Current UTC Date"

	foreach ($IPaddress in ($PublicIP,$InternalIP)) {
		"$DataCenter Edge Screen Log matches for $IPaddress"
		isrx "show log screen-log | match $IPaddress | last $Last" "$($Datacenter)-srx-edge"
		"$DataCenter Core Screen Log matches for $IPaddress"
		isrx "show log screen-log | match $IPaddress | last $Last" "$($Datacenter)-srx-core"

		"$DataCenter Edge Messages Log matches for $IPaddress"
		isrx "show log messages | match $IPaddress | last $Last" "$($Datacenter)-srx-edge"
		"$DataCenter Core Messages Log matches for $IPaddress"
		isrx "show log messages | match $IPaddress | last $Last" "$($Datacenter)-srx-core"

		"$DataCenter Edge Configuration matches for $IPaddress"
		isrx "show configuration | display set | match $IPaddress | last $Last" "$($Datacenter)-srx-edge"
		"$DataCenter Core Configuration matches for $IPaddress"
		isrx "show configuration | display set | match $IPaddress | last $Last" "$($Datacenter)-srx-core"
	}; #end if InternalIP

	"$(get-date (get-date).ToUniversalTime() -f "MMM dd HH:mm:ss") Current UTC Date"
}; #end Get-SRXLogs

Function Get-VPNForm {
<#
	Get-VPNForm "c-p1-psk-aes256-g2-sha-10800"
	Get-VPNForm "c-p2-esp-3des-sha-3600-no"
	
	
	$VPNProposal = "c-p1-psk-aes256-g2-sha-10800"
	$VPNProposal = $VPNProposal.split("-")
	0..5 | foreach  {" $_ $($VPNProposal[$_])" }
	0 c
	1 p1
	2 psk
	3 aes256
	4 g2
	5 sha

	$VPNProposal = "c-p2-esp-3des-sha-3600-no"
	$VPNProposal = $VPNProposal.split("-")
	1..5 | foreach  {" $_ $($VPNProposal[$_])" }
	0 c
	1 p2
	2 esp
	3 3des
	4 sha
	5 3600
	
S2SVPN: CLC / Customer
Location: CLC / Customer
Public IP: 0.0.0.0 / 0.0.0.0
CLC Encrypted Subnets: 0.0.0.0/0 
Customer Encrypted Subnets: 0.0.0.0/0 

Phase 1: CLC / Customer
Mode: Main / Main?
Protocol: ESP / ESP?
EncAlgo: AES256? / AES256?
HashAlgo: SHA256? / SHA256?
PSK Hint: *** / ***
DH Group: Group 2? / Group 2?
Lifetime: 86400? / 86400?
DPD: Off? / Off?
NAT-T: Off? / Off?
Remote ID: N/A? / N/A?

Phase 2: CLC / Customer
EncAlgo: AES256? / AES256?
HashAlgo: SHA256? / SHA256?
PFS: Off? / Off?
DH Group: Group 2? / Group 2?
Lifetime: 86400? / 86400?
#>

	Param(
		$VPNProposal
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }
	$VPNProposal = $VPNProposal.split("-")
	

	if ($VPNProposal[1] -eq "p1") {
		"
		Phase 1: CLC / Customer
		Mode: $($VPNData.ike.mode)
		Protocol: $($VPNData.ipsec.protocol)
		EncAlgo: $($VPNProposal[3])
		HashAlgo: $($VPNProposal[5])
		PSK Hint: *** / ***
		DH Group: $($VPNProposal[4])
		Lifetime: $($VPNProposal[6])
		DPD: $($VPNData.ike.deadPeerDetection)
		NAT-T: $($VPNData.ike.natTraversal)
		Remote ID: $($VPNData.ike.RemoteID)
		"
	} elseif ($VPNProposal[1] -eq "p2") {
		"
		Phase 2: CLC / Customer
		EncAlgo: $($VPNProposal[3])
		HashAlgo: $($VPNProposal[4])
		PFS - DH Group: $($VPNProposal[6])
		Lifetime: $($VPNProposal[5])
		"
	}; #end if VPNProposal

}; #end Get-VPNForm

 
Function ConvertFrom-SRXScreenLogs {
	Param(
		$Logs, # = (isrx "show log screen-log" $Devicename)
		#[Parameter(Mandatory=$True)]$DeviceName
		[switch]$NoConvert
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }
	
	#$Logs = $Logs -join "" -split "\n"
	if (!($NoConvert)) {
		$Logs = ConvertFrom-CharArrayToString -NoClipboard $Logs
	}; # end if NoConvert

	foreach ($line in $Logs) {
		$line = $line -replace "  "," - " -replace "-N0 "," " -replace "-N1 "," " -replace " RT_IDS: "," - " -replace " source: "," - " -replace ", destination: "," - " -replace ", zone name: "," - " -replace ", interface name: "," - " -replace ", action: "," - "  -replace ",",""
		#This uses a little-known trick of "splatting" each line from the -split into these variables, in order. So the first line goes in $Time0, then the next in $Time1, then 3rd line in $DeviceName etc.
		
		if ((get-date(cftt (get-date) -totz utc) -f dd) -lt 10) {
			$Time0,$Time1,$DeviceName,$IDS,$Source,$Destination,$Zone,$Interface,$Action = $line -split " - "
			$Timestamp = "$($Time0) $($Time1)"
		} else {
			$Timestamp,$DeviceName,$IDS,$Source,$Destination,$Zone,$Interface,$Action = $line -split " - "
		}; # end if get-date -f dd -date 2/09/2017
		
		#$line = $line -replace "The last message repeats $N times",$Logs.incrementor[-1] #Pseudo-code to copy the previous line.
		
		#$Timestamp = "$($Line[0]) $($Line[1])" #$(get-date -format yyyy) $($Line[3])"  
		#$Timestamp = get-date ($line[0] + " " + (get-date -format yyyy) + " " + $line[1]) #Still debugging this

		
		$Source = $Source -split ":"
		$Destination = $Destination -split ":"
		$Interface = $Interface -split "[.]"
		
		$Output = New-Object -TypeName psobject
		$Output = $Output | Select-Object Timestamp,Device,IDS,SourceIP,SourcePort,DestinationIP,DestinationPort,Zone,Interface,VLAN,Action
		$Output.Timestamp = $Timestamp 
		$Output.Device = $DeviceName
		$Output.IDS = $IDS
		$Output.SourceIP = $Source[0]
		$Output.SourcePort = $Source[1]
		$Output.DestinationIP = $Destination[0]
		$Output.DestinationPort = $Destination[1]
		$Output.Zone = $Zone
		$Output.Interface = $Interface[0]
		$Output.VLAN = $Interface[1]
		$Output.Action = $Action
		
		$Output #Returns the output, line-by-line.
	}; #end foreach line
}; #end Convert-SRXScreenLogs

Function Get-SRXScreenLogStatistics {
	Param(
		[ValidateSet('AU1-SRX-EDGE','AU1-SRX-CORE','CA1-SRX-EDGE','CA1-SRX-CORE','CA2-SRX-EDGE','CA2-SRX-CORE','CA3-SRX-EDGE','CA3-SRX-CORE','DE1-SRX-EDGE','DE1-SRX-CORE','GB1-SRX-EDGE','GB1-SRX-CORE','GB3-SRX-EDGE','GB3-SRX-CORE','IL1-SRX-EDGE','IL1-SRX-CORE','NE1-SRX-EDGE','NE1-SRX-CORE','NY1-SRX-EDGE','NY1-SRX-CORE','SG1-SRX-EDGE','SG1-SRX-CORE','UC1-SRX-EDGE','UC1-SRX-CORE','UT1-SRX-EDGE','UT1-SRX-CORE','VA1-SRX-EDGE','VA1-SRX-CORE','VA2-SRX-EDGE','VA2-SRX-CORE','WA1-SRX-EDGE','WA1-SRX-CORE')]$DeviceName,
		[Int]$TopResults = 5,
		[Int]$ScreenDepth = 250,
		$Logs = (isrx "show log screen-log | last $ScreenDepth" $Devicename),
		[switch]$NoConvert,
		[switch]$NoConvert2
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }

	if (!($NoConvert)) {
		if (!($NoConvert2)) {
			$Logs = ConvertFrom-SRXScreenLogs $Logs
		}else {
			$Logs = ConvertFrom-SRXScreenLogs $Logs -NoConvert
		}; #end if NoConvert
	}; #end if NoConvert
	foreach ($NoteProperty in ($Logs | Get-Member -MemberType NoteProperty).name) {
		$LogsHarvest = $Logs | group $NoteProperty -NoElement | select Count,Name,PercentOfTotal | sort count -Descending | select -First $TopResults
		try{ 
			for ($i = 0 ; $i -le $Logs.count ; $i++) {
				$LogsHarvest[$i].percentoftotal = [math]::Round((($LogsHarvest[$i].count / $Logs.count)*100),2)
			}; #end for i le Logs.count
		} catch {
		}; #end try
		$NoteProperty
		$LogsHarvest
	}; #end foreach NoteProperty
}; #end Get-SRXScreenLogStatistics


Function Invoke-SRXScreenServer {
		Param(
		$ServerIP,
		[ValidateSet('AU1-SRX-EDGE','AU1-SRX-CORE','CA1-SRX-EDGE','CA1-SRX-CORE','CA2-SRX-EDGE','CA2-SRX-CORE','CA3-SRX-EDGE','CA3-SRX-CORE','DE1-SRX-EDGE','DE1-SRX-CORE','GB1-SRX-EDGE','GB1-SRX-CORE','GB3-SRX-EDGE','GB3-SRX-CORE','IL1-SRX-EDGE','IL1-SRX-CORE','NE1-SRX-EDGE','NE1-SRX-CORE','NY1-SRX-EDGE','NY1-SRX-CORE','SG1-SRX-EDGE','SG1-SRX-CORE','UC1-SRX-EDGE','UC1-SRX-CORE','UT1-SRX-EDGE','UT1-SRX-CORE','VA1-SRX-EDGE','VA1-SRX-CORE','VA2-SRX-EDGE','VA2-SRX-CORE','WA1-SRX-EDGE','WA1-SRX-CORE')]$DeviceName
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }

Invoke-JuniperCliCommand -Command "show log screen-log | match $ServerIP" -Device $Devicename
Invoke-JuniperCliCommand -Command "show log screen-log.0.gz | match $ServerIP" -Device $Devicename
Invoke-JuniperCliCommand -Command "show log screen-log.1.gz | match $ServerIP" -Device $Devicename
Invoke-JuniperCliCommand -Command "show log screen-log.2.gz | match $ServerIP" -Device $Devicename


$j = Invoke-JuniperCliCommand -Command "show configuration | display set | match $ServerIP" -Device $Devicename
$k = $j.split(" ") | select-string "inside_rule*"
$m = Invoke-JuniperCliCommand -Command "show configuration | display set | match $k" -Device $Devicename
$l = $m.split(' /')[-2]


}; #end Invoke-ScreenServer

	
Function Test-ControlVPNStatus {
	Param(
		[ValidateSet("AU1", "CA1", "CA2", "CA3", "DE1", "GB1", "GB3", "IL1", "NE1", "NY1", "SG1", "UC1", "UT1", "VA1", "VA2", "WA1")]
		$DataCenter,
		$AccountAlias,
		$Sitename,
		[switch]$NoTicketOutput
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }; #end if Global
	
	$VPNData = Find-ControlS2SVPN -AccountAlias $AccountAlias -DataCenter $Datacenter -SiteName $Sitename
	if (!($VPNData)) {
		Write-Error "VPN not found."
		break
    }; #end if VPNData
	if (!($NoTicketOutput)) {
		"
S2SVPN: CLC / Customer
Location: $Datacenter / $Sitename
Public IP: $($VPNData.local.address) / $($VPNData.remote.address)
CLC Encrypted Subnets: $($VPNData.local.subnets)
Customer Encrypted Subnets: 
$($VPNData.remote.subnets)

Phase 1: CLC / Customer
Mode: $($VPNData.ike.mode)
Protocol: $($VPNData.ipsec.protocol)
EncAlgo: $($VPNData.ike.encryption)
HashAlgo: $($VPNData.ike.hashing)
PSK Hint: *** / ***
DH Group: $($VPNData.ike.diffieHellmanGroup)
Lifetime: $($VPNData.ike.lifetime)
DPD: $($VPNData.ike.deadPeerDetection)
NAT-T: $($VPNData.ike.natTraversal)
Remote ID: $($VPNData.ike.RemoteID)

Phase 2: CLC / Customer
EncAlgo: $($VPNData.ipsec.encryption)
HashAlgo: $($VPNData.ipsec.hashing)
PFS - DH Group: $($VPNData.ipsec.pfs)
Lifetime: $($VPNData.ipsec.lifetime)
		"
	}; #end if TicketOutput

	"Messages Log:"
	$MessagesLogs = Invoke-JuniperCliCommand -Command "show log messages | match $($VPNData.remote.address)" -Device $DataCenter-srx-core
	if ($MessagesLogs){ 
		$MessagesLogs
	} else {
		"No logged items in Messages log."
	}; #end if MessagesLogs
	
	"VPN Configuration:"
	$JuniperVPNData = try {
	Test-JuniperS2SVPN -DataCenter $DataCenter -PeerPublicIp $($VPNData.remote.address) -PeerSubnet $($VPNData.remote.subnets[0]) -ClcSubnet $($VPNData.local.subnets[0]) 
	} catch {
		Get-FiveSecondKMD -Datacenter $Datacenter -LocalSRXPublicIP $VPNData.local.address -RemoteRouterPublicIP $VPNData.remote.address
		<#
		isrx "request security ike debug-enable local $($VPNData.local.address) remote $($VPNData.remote.address) level 11" $DataCenter-srx-core 
		sleep 5
		isrx "request security ike debug-disable" $DataCenter-srx-core 
		$KMDdata = isrx "show log kmd | match $($VPNData.remote.address) " $DataCenter-srx-core 
		"KMD logs:"
		$KMDdata
		#>
	}; #end Try
	#No Peer or CLC for Phase 1 only.
	$JuniperVPNData
	
}; #end Get-ControlVPNDetails


Function Get-FiveSecondKMD {
	Param(
		[ValidateSet("AU1", "CA1", "CA2", "CA3", "DE1", "GB1", "GB3", "IL1", "NE1", "NY1", "SG1", "UC1", "UT1", "VA1", "VA2", "WA1")]$DataCenter,
		[ipaddress]$LocalSRXPublicIP,
		[ipaddress]$RemoteRouterPublicIP,
		[int]$LastLogs = 1000,
		[int]$Seconds = 5
	); #end Param
	
	$DebugStatus = isrx 'show security ike debug-status' $DataCenter-srx-core 
	
	if ( ($DebugStatus -split "-")[-1].trim() ) {
		isrx "request security ike debug-enable local $($LocalSRXPublicIP) remote $($RemoteRouterPublicIP) level 11" $DataCenter-srx-core 
		sleep $Seconds
		isrx "request security ike debug-disable" $DataCenter-srx-core 
		$KMDdata = isrx "show log kmd | match $($RemoteRouterPublicIP) | last $LastLogs" $DataCenter-srx-core 
		"KMD logs:"
		$KMDdata
	} else {
	"KMD already running:"
	$DebugStatus
	}; # end if ($DebugStatus -split "-")[-1].trim()	

}; #end Get-FiveSecondKMD


Function Get-SRXTunnelStatistics {
	Param(
		[Parameter(Mandatory=$True)]
		[ValidateSet("AU1", "CA1", "CA2", "CA3", "DE1", "GB1", "GB3", "IL1", "NE1", "NY1", "SG1", "UC1", "UT1", "VA1", "VA2", "WA1")]$DataCenter,
		[Parameter(Mandatory=$True)][int]$index,
		$Node = "primary"
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }
	#$stats = isrx "show security ipsec statistics index 300" ca3-srx-core

	$OldTime = get-date
	$TunnelStats = Invoke-JuniperCliCommand -Command "show security ipsec statistics index $Index node $Node" -Device $DataCenter-srx-core
	#$TunnelStats = $TunnelStats  -join "" -split "\n"
	$TunnelStats = ConvertFrom-CharArrayToString -NoClipboard $TunnelStats 

	$OldEncBytes = $TunnelStats | select-string "Encrypted bytes:"
	$OldEncBytes = ($OldEncBytes -split "[:]\s+")[1]

	$OldDecBytes = $TunnelStats | select-string "Decrypted bytes:"
	$OldDecBytes = ($OldDecBytes -split "[:]\s+")[1]

	$OldEncPackets = $TunnelStats | select-string "Encrypted packets:"
	$OldEncPackets = ($OldEncPackets -split "[:]\s+")[1]

	$OldDecPackets = $TunnelStats | select-string "Decrypted packets:"
	$OldDecPackets = ($OldDecPackets -split "[:]\s+")[1]

	$NewTime = get-date
	$TunnelStats = Invoke-JuniperCliCommand -Command "show security ipsec statistics index $Index node $Node" -Device $DataCenter-srx-core
	$TunnelStats = ConvertFrom-CharArrayToString -NoClipboard $TunnelStats 

	$NewEncBytes = $TunnelStats | select-string "Encrypted bytes:"
	$NewEncBytes = ($NewEncBytes -split "[:]\s+")[1]

	$NewDecBytes = $TunnelStats | select-string "Decrypted bytes:"
	$NewDecBytes = ($NewDecBytes -split "[:]\s+")[1]

	$NewEncPackets = $TunnelStats | select-string "Encrypted packets:"
	$NewEncPackets = ($NewEncPackets -split "[:]\s+")[1]

	$NewDecPackets = $TunnelStats | select-string "Decrypted packets:"
	$NewDecPackets = ($NewDecPackets -split "[:]\s+")[1]


	$EncByteIncrease = $NewEncBytes - $OldEncBytes
	$DecByteIncrease = $NewDecBytes - $OldDecBytes
	$EncPacketIncrease = $NewEncPackets - $OldEncPackets
	$DecPacketIncrease = $NewDecPackets - $OldDecPackets

"
Total Seconds: $(($NewTime - $OldTime).TotalSeconds)
Encrypted Packets have increased by: $EncPacketIncrease
Decrypted Packets have increased by: $DecPacketIncrease
Encrypted Bytes have increased by: $EncByteIncrease
Decrypted Bytes have increased by: $EncPacketIncrease
"

}; #end Get-SRXTunnelStatistics
	

#endregion


#region NOC

Function Get-NOCBoxFirstTimeCommands {
	Param(
		[switch]$Veeam,
		[switch]$2012,
		[Array]$Commands = ""
	) #end Param
	if ($2012) {
		#--Server 2012---
	$Commands += 'copy-item "\\10.88.10.231\c$\Users\stephen.gillie\Desktop\Desktop\startrun.lnk" C:\Users\stephen.gillie\Desktop'
	}; #end if 

	#--Server 2012 R2 & Server 2008/R2---
	$Commands += 'New-ItemProperty -Path HKCU:\Software\Microsoft\ServerManager -Name DoNotOpenServerManagerAtLogon -PropertyType DWORD -Value "0x1" -Force'
	$Commands += 'New-ItemProperty -Path HKCU:\Console -Name Quickedit -PropertyType DWORD -Value "0x1" -Force'
	#--NOC shortcuts---
	$Commands += 'copy-item "\\10.88.10.231\c$\Users\stephen.gillie\Desktop\Desktop\Logoff.lnk" "C:\Users\Stephen.Gillie\Desktop\"'
	$Commands += 'copy-item "\\10.88.10.231\c$\Users\stephen.gillie\Desktop\Desktop\Computer Management.lnk" "C:\Users\Stephen.Gillie\Desktop\"'
	#--Powershell shortcut---
	$Commands += 'copy-item "\\10.88.10.231\c$\Users\stephen.gillie\Desktop\Desktop\PowerShell.lnk" "C:\Users\stephen.gillie\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"'
	#--vSphere shortcut---
	$Commands += 'copy-item "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\VMware\VMware vSphere Client.lnk" "C:\Users\stephen.gillie\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\"'
	
	#--Profile---
	$Commands += 'if (!(test-path (split-path $PROFILE))) {md (split-path $PROFILE)}
	if (!(test-path $PROFILE)) {copy-item "\\10.88.10.231\c`$\Users\stephen.gillie\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1" "C:\Users\stephen.gillie\Documents\WindowsPowerShell\Microsoft.PowerShell_profile.ps1"}
	if (!(test-path $PowerGil)) {copy-item "\\10.88.10.231\c`$\Users\stephen.gillie\Documents\WindowsPowerShell\PowerGil.ps1" $PowerGil}
	if (!(test-path $GilCLC)) {copy-item "\\10.88.10.231\c`$\Users\stephen.gillie\Documents\WindowsPowerShell\GilCLC.ps1" $GilCLC}
	if (!(test-path $EnGuard)) {copy-item "\\10.88.10.231\c`$\Users\stephen.gillie\Documents\WindowsPowerShell\EnGuard.ps1" $EnGuard}'
	#if (!(test-path $PROFILE)) {New-Item -Path (split-path $PROFILE) -Name Microsoft.PowerShell_profile.ps1 -ItemType file}'
	
	
	$Commands | clip
}; #end Get-NOCBoxFirstTimeCommands


Function Get-NOCBoxFirstTimeCommandExit {
	Param(
		[Array]$Commands = ""
	) #end Param
	$Commands += ''
	$Commands += ''
	$Commands += ''
		#--Remove shortcuts---
	$Commands += 'remove-item "C:\Users\Stephen.Gillie\Desktop\startrun.lnk"'
	$Commands += 'remove-item "C:\Users\Stephen.Gillie\Desktop\Logoff.lnk"'
	$Commands += 'remove-item "C:\Users\Stephen.Gillie\Desktop\Computer Management.lnk"'
	$Commands += 'remove-item "C:\Users\Stephen.Gillie\Desktop\*.log"'
	$Commands += 'exit'
	$Commands += '#shutdown -l'

	$Commands | clip
	
}; #end Get-NOCBoxFirstTimeCommandExit


Function Get-SendMailTest {
#---sendmail---
$MailMessage = '$hostname = hostname ; Send-MailMessage -to sgta@ctl.io -from SGTA@ctl.io -Subject "Test" -body "Testing from $hostname" -smtps relay.t3mx.com'
return $MailMessage

}; #end Get-SendMailTest


function Connect-NOCBox {
	Param(
	   [Parameter(Mandatory=$True,Position=1)]
	   [string]$NOCBox,
	   [switch]$Secondary
	)
	if ($Secondary) { $NOCName = ($NOCBox + "T3NCCNOC02") } else { $NOCName = ($NOCBox + "T3NCCNOC01") } 

	$cred = Import-Credential -FriendlyName T3N 
	Enter-PsSession -ComputerName $NOCName -Credential $cred -EnableNetworkAccess -Authentication CredSsp

} #end Connect-NOCBox

#endregion

#region utility

Function Resolve-DNSName2 {
	Param(
		$DNSNames
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }
	
$DNSNames | foreach { try {Resolve-DnsName $_ }catch{"$_"}}

}; #end Resolve-DNSName2

function Get-Datacenters {
	Param(
		[switch]$Names
	) #end Param

	if ($Names) {
		$datacenters = "AU1","CA1","CA2","CA3","DE1","GB1","GB3","IL1","NE1","NY1","SG1","UC1","UT1","VA1","VA2","WA1"
	} else {
		$datacenters = Import-Clixml "C:\Workbox\repos\toolbox\PowerShell Modules\Infrastructure\Infrastructure.xml"
	}; #end if 

	return  $datacenters
}; #end Get-Datacenters 

function Get-PuttyLogin {
	Param(
		[Parameter(Mandatory=$True)]
		[string]$Datacenter,
		[string]$Device = "srx"
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }	
	
	#Launch one Putty window for Core, another for CoretoEdge
	start-process $UtilPath\putty
	#If this is an SRX, open a 2nd Putty window for double-hop login to Edge
	if ($Device -eq "srx") {
		start-process $UtilPath\putty
	}; #end if Device
	
	if ($datacenter.length -gt 3) {
		#$ipaddress = (Get-InfrastructureDevice -Name "$Datacenter-$Device-1").ipaddresses.ip
		$DeviceInfo = Find-PasswordStatePassword "$Datacenter"
	} else {
		$DeviceInfo = Find-PasswordStatePassword "$Datacenter-$Device"
	}; #end if datacenter.length
	#$sg1srx = Find-PasswordStatePassword sg1-srx
	
	$DeviceInfo.GenericField4.split(",")[0] | Clip ; 
	#$ipaddress
	write-host "Device Address" ; 
	sleep 5 ; 
	
	$DeviceInfo.UserName | clip ; 
	write-host "username" ; 
	sleep 5 ; 
	
	$DeviceInfo.Password | clip ; 
	write-host "password" ; 
	sleep 5 ; 
	
	#If this is an SRX, continue double-hop login to Edge
	if ($Device -eq "srx") {
		"cli" | clip ; 
		write-host "cli" ; 
		sleep 5; 

		"ssh " + $DeviceInfo.GenericField4.split(",").trim()[1] | clip ; 
		write-host "ssh to Edge" ; 
		sleep 5 ; 

		$DeviceInfo.Password | clip ; 
		write-host "password" ; 
		sleep 5 ; 

		"cli" | clip ; 
		write-host "cli" ; 
	}; #end if Device

	$DeviceInfo = ""

}; #end Get-PuttyLogin

Function Get-PasswordCharacterType {
	Param(
		[Parameter(ValueFromPipeline=$True)]
		$Password = (Get-Clipboard),
		[Switch]$NoClipboard
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }
	$Output = $Password -creplace "[a-z]", ' lower' -creplace "[A-Z]", ' upper'-replace "\d", ' number' -replace '[~`!@#$%^&*(){}\[\]|"<>_+-=\\/?]',' symbol' -replace "[ ]{2,}"," space"
	
	$Output = "- Password pattern: $Output."
	
	if ($NoClipboard) {
		return $Output
	} else {
		$Output | clip
	}
}; #"end Get-PasswordCharacterType

Function Find-ControlServer2 {
	Param(
		$ServerName,
		$AccountAlias
	); #end Param
	
    if ($Global:Toolbox.UsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }
	Find-ControlServer $ServerName -AccountAlias $AccountAlias | select *
}; #end Find-ControlServer2

Function ConvertFrom-ControlPartitions {
	
((Get-Clipboard) -join " " -replace '\\',"\ " -replace " GB","" -replace "%","%`n" ).trim() | clip
Convert-SpaceDeltoHypehnDel

}; #end ConvertFrom-ControlPartitions

Function Convert-ZDTC {
		Param(
			$TicketNumber,
			[switch]$NoClipboard
		); #end Param
	
	$GC = (Get-Clipboard).trim()
	$GC = $GC -replace "https://t3n.zendesk.com/agent/tickets/",""
    if ($GC.length -eq 7) {
        $Ticketnumber = $GC
    }; #end if Get-Clipboard
    
    #Break if no ticket number.
    if (!($Ticketnumber)) {break}
    
    $Newline = "`n"
	[Array]$AliasGAP += $Newline
	[Array]$ServerLine += $Newline
	[string]$VeeamServerName = "VeeamServerName"
	
	$ZenDeskTicketComments = Get-ZenDeskTicketComment $TicketNumber
	$output = @()
	$counter = 0
	foreach ($Comment in $ZenDeskTicketComments) {
		$counterstring = $counter.tostring()
		$counter++
		$PublicComment = if ($Comment.public) {"Public"} else {"Internal"}; #end if Comment
		$CommentBody = $Comment.body -split "`n"
		$UserName = (Get-ZenDeskObject -ObjectId $Comment.author_id -ObjectType User).name
		
		if ($CommentBody[0] -like "Customer Account Alias*") {
			$output += "$($counterstring). $UserName made a Handover Notes $PublicComment update." + $Newline
		} elseif ($CommentBody[0] -like "QI: *") {
			$output += "$($counterstring). $UserName issued a QI." + $Newline
		} elseif ($CommentBody[0] -like "Passing to relevant engineer for appropriate follow up.*") {
			$output += "$($counterstring). Automated post-chat ticket hygiene." + $Newline
		} elseif ($CommentBody[0] -like "Assigning to engineer *") {
			$output += "$($counterstring). Automated post-chat ticket hygiene." + $Newline
		} elseif ($CommentBody[0] -like "Adding chat time:*") {
			$output += "$($counterstring). Automated post-chat ticket hygiene." + $Newline
		} elseif ($CommentBody[0] -like "| General Info | | Chat Start Time:*") {
			$output += "$($counterstring). Chat Transcript attached." + $Newline
		} elseif ($UserName -like "Chat Transcript") {
			$output += "$($counterstring). Chat Transcript attached." + $Newline
		} else {
			$output += "$($counterstring). $UserName made the following $PublicComment update:" + $Newline
			$output += "- " + (ConvertFrom-ParagraphtoBulletList -NoClipboard $CommentBody) + $Newline
			#$output += "- " + (ConvertFrom-ParagraphtoBulletList -NoClipboard $CommentBody[$CommentBodyTopLine..$CommentBodyBottomLine])
		}; # end if PublicComment
		
	}; # end foreach Comment
	$output = $output -replace "Thanks,","" -replace "Hello,","" -replace "CenturyLink Cloud\r\n",""  | select -unique
	$output
}; #end Convert-ZDTC

Function Get-Invocation {
	$MyInvocation
}; #end Get-Invocation

#endregion

#region VMWare
function Get-VMMigrationEvent {
	Param(
	   [Parameter(Mandatory=$True,Position=1)]
	   [string]$VMName,
	   [Parameter(Mandatory=$True,Position=2)]
	   [DateTime]$LastSuccess,
	   [Parameter(Mandatory=$True,Position=3)]
	   [DateTime]$FirstFailure
	)
	if ($FirstFailure -lt $LastSuccess) {
		Throw "Last Success must be before First Failure."
	}; #end if $FirstFailure
	Write-host "Getting events for $VMName..." -f "Green"
	#get-vievent $servername | where {$_.createdtime -gt $lastsuccess} | where {$_.createdtime -le $firstfailure} | select fullformattedmessage
	$VMEvent = Get-VIEvent $VMName
	$LastSuccessDate = Get-Date $LastSuccess
	$FirstFailureDate = get-date $FirstFailure
	$AfterFirstFailure = foreach ($VMEvents in $VMEvent) { 
		$VMEvents | where { 
			$VMEvents.createdtime -le $FirstFailureDate  
		}; #end where
	}; #end foreach VMEvents
	$BetweenEvents = foreach ($VMEvents in $AfterFirstFailure) { 
		$VMEvents | where { 
			$VMEvents.createdtime -ge $LastSuccessDate  
		}; #end where
	}; #end foreach VMEvents
	Write-host "Got $($BetweenEvents.count) events for $VMName." -f "Green"
	$BetweenEvents  | select createdtime, fullformattedmessage  -d | ft
}; #end Get-VMMigrationEvent


function Convert-CPUReady { 
<#
.SYNOPSIS
	 Converts between CPU summation and CPU % ready values
.DESCRIPTION
	 Author   : Stephen Gillie (found online)
	 Last edit: 5/7/2016
.PARAMETER Frequency
	 Required.
	 VMWare Performance Graph from which the CPU Ready value was taken.
.PARAMETER CPUReadyValue
	 Required.
	 CPU Ready value from the VMWare Performance Graph. 
.EXAMPLE
	 Math-CPUReady -Frequency PastMonth -CPUReadyValue 244332
 .LINK
	 https://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2002181
#>
  	Param(
 		[Parameter(Mandatory=$True,Position=1)]
 		[ValidateSet("Realtime","PastDay","PastWeek","PastMonth","PastYear")]
 		[string]$Frequency,
 		[Parameter(Mandatory=$True,Position=2)]
 		[int]$CPUReadyValue,
 		[switch]$Raw
 	) #end Param
 
 	[int]$FreqDiv = 0;	
 	switch ($Frequency) { 
		 "Realtime" {$FreqDiv = 200 }
		 "PastDay" {$FreqDiv = 3000 }
		 "PastWeek" {$FreqDiv = 18000 }
		 "PastMonth" {$FreqDiv = 72000 }
		 "PastYear" {$FreqDiv = 864000 }
		 default {"CPUReady could not be determined."}
	 }; #end switch
 
 	$outval = $CPUReadyValue/$FreqDiv
 	$roundval = [math]::Round($outval,2)
 	if ($Raw) {
 	return $roundval / 100
 	} else {
 
 		if ($outval -lt 5) {
 			write-host -f y "CPU Ready is $($roundval)%."
 		} else {
 			write-host -f y "CPU Ready is $($roundval)%" -nonewline;
 			write-host -f r " This may impact VM performance."
 		}; #end if outval lt 5
 
 	}; #end if Raw
 
}; #end Convert-CPUReady


#endregion
 
 Function Get-CachedUserFromID { 
<#
	.SYNOPSIS
	Builds the CacheTable if necessary, then returns it. Acts as a caching callback wrapper.
	.DESCRIPTION
	Author   : Stephen Gillie
	Last edit: 05/06/2017
	.EXAMPLE
	Get-CachedUserFromID Get-SlackUser U095H3F1B
#>

  [CmdletBinding()]
    Param( 
		[Parameter(Mandatory=$True,Position=0)][string]$FunctiontoCache,
		[Parameter(Mandatory=$True,ValueFromPipeline=$True,Position=1)][Array]$InputCacheData,
        [String]$CachePath = ([environment]::getfolderpath("mydocuments")),
        [String]$CacheFilename = ($CachePath + "\" + $FunctiontoCache + ".json"),
		[Array]$CacheTable = (Get-Content -raw $CacheFilename -ErrorAction SilentlyContinue | ConvertFrom-Json),
        [String]$FieldToReturn = "name",
        [String]$FieldToKey = "id",
        [String]$AltFieldToReturn = "real_name",
        [String]$SideIndicator = "=>",
		[Array]$OutCheck = $InputCacheData
    ); #end Param
	

	Write-Verbose "File $CacheFilename"
	Write-Verbose "Starting InputVar $InputCacheData"
	
	Write-Verbose "Pre-diff InputVar $InputCacheData"
    if ($InputCacheData -AND $CacheTable) {
		[Array]$InputCacheData = try{
			(Compare-Object ($CacheTable.$FieldToKey | sort -Unique) ($InputCacheData | sort -Unique) | where {$_.SideIndicator -match $SideIndicator}).inputobject
		}catch{
			$InputCacheData
		}; #end try
    }; #end If InputCacheData
	$InputCacheData = ($InputCacheData | sort -Unique)
	Write-Verbose "Diffed InputVar $InputCacheData"
    
    #Lookup any new UserIDs, add them to the table.
    foreach ($DataItem in $InputCacheData) { 
		Write-Verbose "$FunctionToCache $DataItem"
        [Array]$CacheTable += (& $FunctiontoCache $DataItem)
    }; #end foreach DataItem
    
    #Write the table, then immediately read from it, to return.
	Write-Verbose "CachedData $($CacheTable.$FieldToKey)"
    $CacheTable | ConvertTo-Json > $CacheFilename
	Write-Verbose "Ending InputVar $InputCacheData"
	$OutputCacheData = (Get-Content -raw $CacheFilename -ErrorAction SilentlyContinue | ConvertFrom-Json )
	#This only seems to work if the property is called on the where output, maybe to convert this into another object type?
	Write-Verbose "First OutputVar $OutputCacheData"
	
	if (($OutputCacheData | where {$_.$FieldToKey -in $OutCheck}).$AltFieldToReturn) {
		$OutputCacheData = ($OutputCacheData | where {$_.$FieldToKey -in $OutCheck}).$AltFieldToReturn
	} else {
		$OutputCacheData = ($OutputCacheData | where {$_.$FieldToKey -in $OutCheck}).$FieldToReturn
	}; #end if $OutputCacheData
	Write-Verbose "Last OutputVar $OutputCacheData"
	return $OutputCacheData
 }; #end Get-CachedUserFromID


#region Slack
#Send-SlackMessage -apikey (fcr slack).entries.value -username stephengillie -channel "james-test" -message "Test!"

Function Get-SlackChannelMessagesAsText {
<#
.SYNOPSIS

.DESCRIPTION
Get-SlackChannelMessagesAsText
.EXAMPLE
Get-SlackChannelMessagesAsText
#>
[CmdletBinding()]
    param
    (
		[string]$ChannelName,
		[string]$ChannelID,
		[int]$Count="10",
		[string]$APIKey = ((fcr slack).entries.value[1])
    )
	$origin = get-date "1/1/1970"
    if ($env:ToolboxUsageLog) {
        Write-UsageLog -Invocation $MyInvocation -Verbose:$VerbosePreference
    }
    if (!($ChannelID)) {
		$ChannelID = Invoke-SlackApi -Method channels.list -Token $APIKey | select -expand channels | where {$_.name -eq $channelname} | foreach {$_.ID}
    }; #end if ChannelID
    #$ChannelID = Get-SlackChannels -apikey $APIKey | where {$_.name -eq $channelname} | foreach {$_.ID}
	Write-Verbose $ChannelID

    $slackurl = "https://slack.com/api/channels.history?token=$APIKey&channel=$channelid&count=$count&pretty=1"
    $updates = Invoke-WebRequest -Uri $slackurl -UseBasicParsing
    $updates = $updates.Content | ConvertFrom-Json

    [Array]$output = @{}

    foreach ($update in ($updates.messages | where {$_.user -ne $null})) {
		#$time = Convert-FromUnixdate -UnixDate ($update.ts)
		#$timestring = get-date ($time ) -UFormat %R
		$timestring = 	$origin.AddSeconds($update.ts)
		$UserName = if ($update.user) {Get-CachedUserFromID Get-SlackUser $update.user} else {"NoUserID"}
		#$line = $timestring + " - " + (Get-SlackUser -apikey $APIKey -user $update.user | foreach {$_.real_name}) + " - " + $update.text
		$line = $timestring + " - " + $UserName + " - " +  $update.text
		$output += $line
    }
    [Array]::Reverse($output)
    return $output
}; #end Get-SlackChannelMessagesAsText


#endregion

#>
#region ElasticSearch
$baseUrl = 'http://10.170.15.15:9200/devices/device/_search'

function Get-AllDevices {
    $query = '
    {
        "query":{
        "match_all": {}
        }, "size": 700
    }'
    
    $response = Invoke-RestMethod $baseUrl -Method Post -Body $query -ContentType 'application/json'
    if($response.hits.total -gt 0) {
        return $response.hits.hits | select -Property _source
    }
    return $null
}

function Get-AllDevicesFromDC {
[Cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)][string]$DCName
    )

    $query = '
    {
        "query": {
            "term": {
                "datacenter": "' + $DCName + '"
            }
        },
        "size": 500
    }'
    
    $response = Invoke-RestMethod $baseUrl -Method Post -Body $query -ContentType 'application/json'
    if($response.hits.total -gt 0) {
        return $response.hits.hits | select -Property _source
    }
    return $null
}

function Get-AllDevicesFromProperty {
[Cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Property,
        [Parameter(Mandatory=$true)][string]$Value
    )

    $query = '
    {
        "query": {
            "term": {
                "' + $Property + '": "' + $Value + '"
            }
        },
        "size": 500
    }'
    
    $response = Invoke-RestMethod $baseUrl -Method Post -Body $query -ContentType 'application/json'
    if($response.hits.total -gt 0) {
        return $response.hits.hits | select -Property _source
    }
    return $null
}

function Get-DevicesViaWildCard {
[Cmdletbinding()]
    param (
        [Parameter(Mandatory=$true)][string]$Property,
        [Parameter(Mandatory=$true)][string]$Value
    )

    $query = '
    {
        "query": {
            "wildcard": {
                "' + $Property + '": "' + $Value + '"
            }
        },
        "size": 200
    }'
    
    $response = Invoke-RestMethod $baseUrl -Method Post -Body $query -ContentType 'application/json'
    if($response.hits.total -gt 0) {
        return $response.hits.hits | select -Property _source
    }
    return $null
}

#Get-AllDevices
#Get-AllDevicesFromDC -DCName "wa1"
#Get-AllDevicesFromProperty -Property "type" -Value "netoob"
#Get-DevicesViaWildCard -Property "type" -Value "net*"

#endregion

 


new-alias -name ghn -value Get-HandoverNotes -force
New-Alias -Name fc2 -Value Find-ControlServer2 -force
New-Alias -Name fc3 -Value Find-ControlServer3 -force
