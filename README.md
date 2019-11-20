# Powershell
A variety of functions I have made for day to day use that exist in my profile.ps1

#### Get-MOTD
* This is what will load up whenever Powershell is opened

#### Get-OnlineHosts
* Checks if host is pingable

#### Send-PrinterTestPage
* Adds a printer to the host, sends a test page to the printer, and then removes the printer

#### aux_Set-Verbosity.ps1
* All my functions will have the `$v` flag that can be set.  It will trigger this function which will either turn on or off verbosity

#### Get-HostUserActivity
* This function was an honest attempt at getting information about what users have been logged into what hosts.  There are a lot of articles out there as to why this is an absolute nightmare to do.  I still need to work on this and make it more reliable but for right now it is a good first start for gathering information.  
