<#
.SYNOPSIS
Gets the user logons of our hosts and or gets the hosts a user has logged on to 

.DESCRIPTION
Maintains a local database in our program files that contains all the logon/logoff activity of all our hosts past and present starting from 7/22/2018.  There is a GPO that runs in the background every day at 7am that will update every single host's database.  Each host has its own xml file and that contains an importable object that we use to parse for information.

Parameter: ComputerName
This can be a single host or a list of hosts.  "computername1" or "computername1","computername2"

Parameter: UpdateNow
This will update the database of the hosts that you entered with the ComputerName Parameter and if none were entered and the AllHosts parameter was not set, then it will error out, else it will update all the hosts' xml file

Parameter: IdleList
This wont display login information but instead will tell you which hosts you have entered that do not have any recent logins

Parameter: AllHosts
Will run Get-HostList -Clients to get a current list of all our hosts

Parameter: User
Will parse our database and find any hosts that the given user has logged into

.EXAMPLE
PS C:\windows\system32> Get-HostUserActivity -ComputerName "computername1","computername2"
Returns the recent logons of the hosts computername1 and computername2.

.EXAMPLE
PS C:\windows\system32> Get-HostUserActivity -AllHosts
Returns the recent logons of all of our hosts

.EXAMPLE
PS C:\windows\system32> Get-HostUserActivity -AllHosts -IdleList
Returns any host that has not had a recent login

.EXAMPLE
PS C:\windows\system32> Get-HostUserActivity -User "picnicsecurity"
Returns the hosts that have had the User picnicsecurity logged into it

.EXAMPLE
PS C:\windows\system32> Get-HostList | Get-HostUserActivity -LoggedOnUsers
Returns the users that are currents logged into all of our hosts

.EXAMPLE
PS C:\windows\system32> Get-HostList -OS win7 | Get-HostUserActivity -IdleList -ErrorList
Returns a list of all the hosts that have had never been logged into for all of our windows 7 hosts

.EXAMPLE
PS C:\windows\system32> Get-HostList | Get-HostUserActivity -LoggedOnUsers -IdleList
Returns a list of all the hosts in our domain that have no users currently logged into them

.EXAMPLE
PS C:\windows\system32> Get-HostUserActivity -User "picnicsecurity"
Returns the hosts that have had the User picnicsecurity logged into it

.EXAMPLE
PS C:\windows\system32> Get-HostUserActivity -AllHosts -UpdateNow -UserDatabase
Updates the files in our database for all current hosts and users.  This is what our GPO does.  It will take a very long time to run and should only be done once a day early in the morning
#>
function Get-HostUserActivity {

	[CmdletBinding(DefaultParameterSetName = "UserActivity")]
	param(
		[Parameter(Mandatory = $false,Position = 0,ValueFromPipeline = $true)] [string[]]$ComputerNames,#A list of hosts we want to get the logon information from
		[Parameter(Mandatory = $false,ValueFromPipeline = $false)] [switch]$UpdateNow,#Instead of using the file generated in the morning, generates a new one right now for the hosts specified
		[Parameter(Mandatory = $false,ValueFromPipeline = $false)] [switch]$IdleList,#Gets a list of the idle hosts
		[Parameter(Mandatory = $false,ValueFromPipeline = $false)] [switch]$AllHosts,#Gets user activity for all our hosts
		[Parameter(Mandatory = $false,ValueFromPipeline = $false)] [string]$User,#Gets the name of all the hosts a user has been logged into    
		[Parameter(Mandatory = $false,ValueFromPipeline = $false,ParameterSetName = "LoggedOnUsers")] [switch]$LoggedOnUsers,#Will return the users currently logged into the provided hosts
		[Parameter(Mandatory = $false,ValueFromPipeline = $false)] [switch]$ErrorList,#Will return the list of hosts that we could not connect to (badlist variable)
        [Parameter(Mandatory = $false,ValueFromPipeline = $false)] [switch]$NoLog,#Will prevent log call
		[Parameter(Mandatory = $false,ValueFromPipeline = $false)] [switch]$v #Verbosity switch
	)

	begin {
        
    # Function Database Logging
    if(!$NoLog){ Out-File "C:\Databases\FunctionLogs\Set-HostAttribute.csv" -InputObject $("$env:USERNAME,$(Get-Date -UFormat %Y%m%d%I%M)") -Append }

		if ($v) { aux_Set-Verbosity -on } else { aux_Set-Verbosity -Off }
		Write-Verbose "Starting"
		# The start blocks are in the order they are in since each of them return after executed and thus prevent any extra processing

		### All Hosts Start Block ###
		if ($AllHosts) {
			Write-Verbose "Gathering all hosts"
			$ComputerNames = Get-HostList | Remove-Null
			Write-Verbose "`$ComputerNames | Get-HostUserActivity -LoggedOnUsers:`$LoggedOnUsers -UpdateNow:`$UpdateNow -UserDatabase:`$Userdatabase -IdleList:`$IdleList -ErrorList:`$ErrorList -v:`$v"
			$ComputerNames | Get-HostUserActivity -LoggedOnUsers:$LoggedOnUsers -UpdateNow:$UpdateNow -IdleList:$IdleList -ErrorList:$ErrorList -v:$v -NoLog
			return
		}

		### Update Now Start Block ###
		if ($UpdateNow) {
			Write-Verbose "Updating the Database"
			$updateList = @()
			$badList = @()
			return
		}

		### Looged On User Start Block ###
		if ($LoggedOnUsers) {
			Write-Verbose "Working with logged on user"
			$computerList = @()
			$userList = @()
			$timestampList = @()
			$idlehostsList = @()
			$badList = @()
			return
		}

		### User Start Block ###
		if ($User) {
			Write-Verbose "Working with user"
			return
		}

		### Default Start Block ###
		Write-Verbose "defaults set"
		$hostList = New-Object System.Collections.ArrayList
		$idlehostsList = @()
		$badList = @()
	}

	process {

		### Update Now Process Block ##
		if ($UpdateNow) {
			Write-Verbose "Processing in update now block"
			if ($_) {
				$currentHost = $_.ToLower()
				if (Assert-HostInDomain $currentHost) {
					Write-Verbose "Add $currentHost to updateList"
					$updateList += $currentHost
				} else {
					if ($ErrorList) {
						Write-Verbose "Adding $currentHost to errorList"
						$badList += $currentHost
					}
				}
			} else {
				$tempList = @()
				$tempList += $ComputerNames | Remove-Null | Sort -Unique
				foreach ($computer in $tempList) {
					if (Assert-HostInDomain $computer) {
						Write-Verbose "Add $computer to updateList"
						$updateList += $computer.ToLower()
					} else {
						if ($ErrorList) {
							Write-Verbose "Adding $computer to errorList"
							$badList += $computer
						}
					}
				}
			}
			return
		}

		### Logged On Users Process Block ##
		if ($LoggedOnUsers) {
			Write-Verbose "Processing in logged on users block"
			# When I redid my functions to support pipeline, I also wanted to make sure they could handle named input and since efficiency is just clever laziness, I just piped the given list of ComputerNames back into the function
			if ($_) {
				$currentHost = $_.ToLower()
				Write-Verbose "Working with $currentHost"
			} else {
				#First we do a null check
				if (!($ComputerNames | Remove-Null)) {
					Write-Verbose "Nothing in the pipeline and nothing in ComputerNames"
					return
				} else {
					# #recursion?
					Write-Verbose "`$ComputerNames | Remove-Null | Sort | Get-HostUserActivity -LoggedOnUsers"
					$ComputerNames | Remove-Null | Sort | Get-HostUserActivity -LoggedOnUsers -NoLog
					Write-Verbose "Done"
					return
				}


			}

			if (!(Get-OnlineHosts $currentHost)) {
				if ($ErrorList) {
					Write-Verbose "Adding $currentHost to bad list"
					$badlist += $currentHost
					return
				}
				Write-Verbose "Could not connect to $currenthost"
				return
			}

			#We are just checking how many users currently have explorer.exe active which gives an accurate assement of who is active on the computer
			$activeUsers = Get-WmiObject -Class Win32_Process -Filter "name='explorer.exe'" -ComputerName $currentHost
			if ($activeUsers) {

				$activeUsers | ForEach-Object {

					<# COMPUTER #>
					$computerlist += $currentHost

					<# USER #>
					$currentuser = $_.GetOwner() | Select-Object -ExpandProperty User
					$userlist += $currentuser

					<# TIMESTAMP #>
					# To get the time timestamp we first make the variable equal to the object 
					$timestamp = $_
					# Next we select the object property CreationDate and give it the label 'Since' and use wmi's built in ConvertToDateTime method to convert the string accordingly (20180810082116.900648-240 => Friday, August 10, 2018 8:21:16 AM)
					$timestamp = $timestamp | Select-Object @{ label = 'Since'; expression = { $_.ConvertToDateTime($_.CreationDate) } } | Select-Object -ExpandProperty Since
					# Lastly we use Get-Date to format our newly created date (Friday, August 10, 2018 8:21:16 AM => 8/10/2018 8:21 AM)
					$timestamp = Get-Date -Format g $timestamp
					$timestamplist += $timestamp

				}

			} else {
				#If there are no users logged in we will just give it a value of "none"
				$computerlist += $currentHost
				$userlist += ""
				$timestamplist += ""
				Write-Verbose "Adding $currentHost to idle list"
				$idlehostsList += $currentHost
			}
		}

		### User Process Block ###
		if ($User) {
			$username = $User
			Write-Verbose "Processing in user block with `"$Username`""
			#Dont need to verify if the user is part of our domain currently since our database keeps historical information
			$userObj = New-Object System.Collections.ArrayList
			Write-Verbose "Checking which hosts $Username has logged into"
			Get-ChildItem -Directory "C:\Databases\HostUserActivity\" | ForEach-Object {
				$computer = $_.Name
				$hostUserActivityObj = Import-Clixml "C:\Databases\HostUserActivity\$computer\$computer"
				$hostUserActivityObj | ForEach-Object {
					if ($_. 'User Name' -eq $username) {
						$tempObj = New-Object System.Object
						$tempObj | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $computer
						$tempObj | Add-Member -MemberType NoteProperty -Name "Logon Time" -Value $($_. 'Logon Time')
						$tempObj | Add-Member -MemberType NoteProperty -Name "Logoff Time" -Value $($_. 'Logoff Time')
						$userObj.Add($tempObj) | Out-Null
					}
				}
			}

			$userObj | Sort-Object -Unique -Property 'Logon Time' -Descending
			return
		}


		### Default Process Block ###
		if ($_) {
			if ($LoggedOnUsers -or $User) { return }
			Write-Verbose "Processing in default block"
			$computer = $_
			Write-Verbose "Checking $computer"
			if (!(Test-Path "C:\Databases\HostUserActivity\$computer\$computer")) {
				Write-Verbose "No database file for host"
				if (Assert-HostInDomain $computer) {
					Write-Verbose "$computer is in our domain but does not have a database file.  Add it to the database by using the UpdateNow flag or wait until the next update cycle"
				} else {
					Write-Verbose "$computer is not in our domain either"
				}
				if ($ErrorList) {
					$badlist += $computer
				}
			} else {
				if (!$(Import-Clixml "C:\Databases\HostUserActivity\$computer\$computer")) {
					if ($IdleList) {
						Write-Verbose "Adding $computer to idleList"
						$idlehostsList += $computer
					}
				} else {
					#Show recent logons and tell the user when the database was last updated
					$activity = Import-Clixml "C:\Databases\HostUserActivity\$computer\$computer"
					if (!$IdleList) {
						Write-Output "Warning: Deprecated Function"
						Write-Output "This function is not going to be entirely accurate and should only be used as a reference point"
						Write-Output "Most recent logins on $computer`: (last updated $(Get-ChildItem "C:\Databases\HostUserActivity\$computer\$computer" | Select-Object -ExpandProperty LastWriteTime))"
						$activity | Sort-Object -Property 'Logon Time' -Descending
					}
				}
			}
		} else {
			# makes call to function while in function, is this recursion ?
			Write-Verbose "Piping computer names back into function"
			$ComputerNames = $ComputerNames | Remove-Null | Sort
			$ComputerNames | Get-HostUserActivity -IdleList:$IdleList -ErrorList:$ErrorList -v:$v -NoLog
			Write-Verbose "Done"
			return
		}


	}

	end {

		Write-Verbose "Ending"

		### Update Now End Block ###
		if ($UpdateNow) {

			#A lot of the code used here was from https://blogs.technet.microsoft.com/heyscriptingguy/2015/11/26/beginning-use-of-powershell-runspaces-part-1/  Very interesting read

			[runspacefactory]::CreateRunspacePool() | Out-Null
			$SessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
			$RunspacePool = [runspacefactory]::CreateRunspacePool(
				1,#Min Runspaces
				20 #Max Runspaces
			)
			$PowerShell = [powershell]::Create()
			$PowerShell.RunspacePool = $RunspacePool
			$RunspacePool.Open()
			$jobs = New-Object System.Collections.ArrayList

			Write-Output "Updating Database..."
			Write-Output "Please be patient as this can take several minutes"
			foreach ($hostname in $updateList) {

				$PowerShell = [powershell]::Create()
				$PowerShell.RunspacePool = $RunspacePool

				<#
                This is the heart of the thread block.  This is what each thread will be doing.  
                First we check if there is a directory for a host and if not we make one.
                Next we setup our output directory in such a way that when we call Start-Process on WinLogOnView it will accept our parameters
                WinLogOnView is cmd so getting its output is messy at best so instead we just output it to a csv and use powershell to convert said csv into a series of objects for us
                The first line in the file is the header and the next 5 are the 5 most recent logins and those are what we want
                We change the Interactive (2) and Remote Interactive (10) to Local and Remote respectively 
                We then export the newly made object into xml for later use (see user block above) 
                #>
				[void]$PowerShell.AddScript({

						param($hostname)

						if (!(Test-Path -Path "C:\Databases\HostUserActivity\$hostname")) {
							New-Item -ItemType Directory -Path "C:\Databases\HostUserActivity\$hostname" -Force
						}

						#Example Output: C:\Databases\HostUserActivity\booop\7_22_18_2_29.csv
						$outputDirectory = "C:\Databases\HostUserActivity\$hostname\$($(Get-Date -Format %M_%d_%y_%h_%m)+".csv")"

						$tempout = "`"" + $outputDirectory + "`""

						#Call winlogonview to gather the information
						$FQDName = $hostname + $currentdomain
						Start-Process "C:\Program Files (x86)\NirSoft\WinLogOnView\WinLogOnView.exe" -ArgumentList "/source 2 /server $FQDName /scomma $tempout" -Wait

						#Get all the logins from host and convert it into standard powershell objects
						$output = Get-Content -Path $outputDirectory | ConvertFrom-Csv

						#Remove all sessions that do not have a value
						$output = $output | Where-Object { ($_.Duration -ne "") -and ($_. 'Logon Type' -ne "") -and ($_. 'User Name' -notlike "*admin") -and ($_. 'User Name' -ne "Administrator") -and ($_. 'User Name' -ne "ranger") }

						#Removes the "Logon ID" and "Network Address" attributes from the list
						$output = $output | Select-Object -Property "User Name","Logon Type","Logon Time","Logoff Time","Duration"
						$output = $output | Sort-Object -Property 'Logon Time' -Descending

						#Only gets the first 6 lines since we only want the 5 most recent logins and the first line is the header 
						$temp = @()
						$counter = 0
						foreach ($login in $output) {
							if ($counter -eq 5) {
								break
							} else {
								if ($login. 'Logon Type' -like "Interactive*") {
									$login. 'Logon Type' = "Local"
								}
								if ($login. 'Logon Type' -like "Remote Interactive*") {
									$login. 'Logon Type' = "Remote"
								}
								$temp += $login
								$counter++
							}
						}
						$output = $temp
						$output | Export-Clixml "C:\Databases\HostUserActivity\$hostname\$hostname"

					})
				[void]$PowerShell.AddArgument($hostname)
				$Handle = $PowerShell.BeginInvoke()
				$temp = '' | Select-Object PowerShell,Handle
				$temp.PowerShell = $PowerShell
				$temp.handle = $Handle
				[void]$jobs.Add($temp)
			}

			#cleanup cleanup everybody everywhere cleanup cleanup
			$jobs | ForEach-Object {
				$_.PowerShell.EndInvoke($_.handle)
				$_.PowerShell.Dispose()
			}
			$jobs.Clear()
			Write-Verbose "Database entries updated"

			#Making recursive call
			$updateList | Get-HostUserActivity -IdleList:$IdleList -ErrorList:$ErrorList -User:$User -LoggedOnUsers:$LoggedOnUsers -v:$v -NoLog
		}

		### Looged On User Return Block ###
		if ($LoggedOnUsers) {

			Write-Verbose "ending logged on users"
			#First we create an arraylist that will hold our objects 
			$loginObj = New-Object System.Collections.ArrayList

			#Next we construct our tempObj by iterating through our lists
			for ($i = 0; $i -lt $($computerlist.Length); $i++) {

				$tempObj = New-Object System.Object
				$tempObj | Add-Member -MemberType NoteProperty -Name "Hostname" -Value $($computerList[$i])
				$tempObj | Add-Member -MemberType NoteProperty -Name "User" -Value $($userList[$i])
				$tempObj | Add-Member -MemberType NoteProperty -Name "Since" -Value $($timestampList[$i])

				#Then we add the newly made object to our arraylist and repeat
				$loginObj.Add($tempObj) | Out-Null
			}

			#Lastly we print out the object
			$loginObj | Format-Table


		}

		### User End Block ###
		if ($User) {}

		### Default End Block ###
		if ($hostList) {}

		### Error List End Block ### 
		if ($ErrorList) {
			Write-Verbose "Printing error list"
			$errorObj = New-Object System.Collections.ArrayList
			for ($i = 0; $i -lt $($badList.Length); $i++) {
				$tempobj = New-Object System.Object
				$tempobj | Add-Member -MemberType NoteProperty -Name "Unreachable" -Value $($badList[$i])
				$errorObj.Add($tempObj) | Out-Null
			}
			$errorObj | Format-Table
		}

		### Idle List End Block ###
		if ($IdleList) {
			Write-Verbose "Printing idle list"
			$idleObj = New-Object System.Collections.ArrayList
			for ($i = 0; $i -lt $($idlehostsList.Length); $i++) {
				$tempobj = New-Object System.Object
				$tempobj | Add-Member -MemberType NoteProperty -Name "Idle" -Value $($idlehostsList[$i])
				$idleObj.Add($tempObj) | Out-Null
			}
			$idleObj | Format-Table
		}



	}
}
