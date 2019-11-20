<#
.SYNOPSIS
Prints a test page on a given printer

.DESCRIPTION
This function will add a printer to the current host and then send a test page to the printer and then remove the printer 
#>
function Send-PrinterTestPage {

	param(
		[Parameter(Mandatory = $true,Position = 0)] $Printers,
    [Parameter(Mandatory = $true,Position = 1)] $printserver,
		[switch]$v
	)

  # Function Database Logging
  Out-File "C:\Databases\FunctionLogs\Send-PrinterTestPage.csv" -InputObject $("$env:USERNAME,$(Get-Date -UFormat %Y%m%d%I%M)") -Append

	if ($v) { aux_Set-Verbosity -on } else { aux_Set-Verbosity -Off }

	$printerlist = New-Object System.Collections.ArrayList

	foreach ($printer in $Printers) {
		$printerlist += $printer
		$printerpath = "\\$printserver\$printer"
		Write-Verbose "Adding $printerpath"
		Add-Printer -ConnectionName $printerpath
	}

	foreach ($tmp in $(Get-WmiObject Win32_Printer)) {
		Write-Verbose "Working with $printer"
		if ($printerlist.Contains($(($($tmp.Name).Split("\"))[3]))) {
			Write-Output "Sending test page to $printer"
			$tmp.PrintTestPage() *> $null

		}
	}

	foreach ($tmp in $(Get-WmiObject Win32_Printer)) {
		Remove-Printer -Name $($tmp.Name)
	}


	Write-Output "Test Page(s) Sent"

}
