<#
.SYNOPSIS
Sets the global verbose,warning,error, and debug variables

.DESCRIPTION
Used by most functions with the $v flag, toggles verbose output on or off.  Regardless of the verbose switch being on or off, we keep errors on.
#>
function aux_Set-Verbosity {
	[CmdletBinding(DefaultParameterSetName = "off")]
	param(
		#off
		[Parameter(ParameterSetName = "off",Mandatory = $true)] [switch]$off,
		#on
		[Parameter(ParameterSetName = "on",Mandatory = $true)] [switch]$on
	)
    
  # Function Database Logging
  Out-File "C:\Databases\FunctionLogs\aux_Set-Verbosity.csv" -InputObject $("$env:USERNAME,$(Get-Date -UFormat %Y%m%d%I%M)") -Append

	if ($on) {
		$global:VerbosePreference = 'Continue'
		$global:WarningPreference = 'Continue'
		$global:ErrorActionPreference = 'Continue'
		$global:DebugPreference = 'Continue'
		Write-Verbose "Verbosity Set"
	}

	if ($off) {
		$global:VerbosePreference = 'SilentlyContinue'
		$global:WarningPreference = 'SilentlyContinue'
		$global:ErrorActionPreference = 'Continue'
		$global:DebugPreference = 'SilentlyContinue'
	}

}
