<#
.SYNOPSIS
Determines if a host is pingable 

.DESCRIPTION
Creates a small and efficient ICMP packet to test the pingablity of a host to determine if it is up or not 

Parameter: ComputerName
This can be a single host or a list of hosts.  "computer1" or "computer1","computer2".  Can handle the pipeline
#>
function Get-OnlineHosts {
	[CmdletBinding(DefaultParameterSetName = "OnlineHost")]
	param(
		[Parameter(Mandatory = $true,Position = 0,ValueFromPipeline = $true)] [string[]]$ComputerName
	)

	begin {
    # Function Database Logging
    Out-File "C:\Databases\FunctionLogs\Get-OnlineHosts.csv" -InputObject $("$env:USERNAME,$(Get-Date -UFormat %Y%m%d%I%M)") -Append
		$out = @()
	}
	process {
		#Forcing pipeline input
		if ($ComputerName -and !$_) {
			$ComputerName | Get-OnlineHosts
			return
		}
		$_ = $_.Trim()
		if ((Test-Connection -ComputerName $_ -BufferSize 16 -Count 1 -Quiet -ErrorAction SilentlyContinue)) {
			$out += $_
		}
	}
	end {
		if ($out) { $out }
	}
}
