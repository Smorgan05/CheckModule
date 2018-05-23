# Install Checker function
function Install-Check{

Param(
		[Parameter(Mandatory=$True,Position=1)][string]$Program
)

# Throw error if Program var is empty
if (!$Program){Throw "You must supply a value for -Program" }

# Load Necessary Libraries
$GetLastWrite = $PSScriptRoot + '\Get-RegistryKeyLastWriteTime.psm1'; Import-Module $GetLastWrite
$GetPEArch = $PSScriptRoot + '\Get-PEArchitecture.psm1'; Import-Module $GetPEArch

# Declare Necessary Functions

	# Get the Software List
	function Get-RegUninstallInfo {
		[cmdletbinding()]
		[OutputType([UninstallInfo])]
		param()

		class UninstallInfo {
			[string] $DisplayName
			[string] $DisplayVersion
			[string] $UninstallString
			[string] $ModifyPath
			[string] $ProductCodes
			[string] $InstallLocation
			[string] $InstallDate
			[int] $EstimatedSize
			[string] $InnoSetupVersion
			[string] $ChildName
			[string] $FullPath
			[string] $Arch
		}
		$paths = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall', 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall', 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall'
		(Get-ChildItem $paths).where{$_.getvalue("DisplayName")}.Foreach{
			$installDate = $_.GetValue("InstallDate")
			$version = $_.GetValue("DisplayVersion")
			if (!$installDate) {$installDate = (Get-RegistryKeyTimestamp -RegistryKey $_).LastWriteTime.ToShortDateString()} else {$installDate = $installDate.Substring(4,2) + '/' + $installDate.Substring(6,2) + '/' + $installDate.Substring(0,4)}
			if ((!$_.GetValue("DisplayVersion")) -and ($_.GetValue("DisplayName") -match '(\d+).*')){$version = $_.GetValue("DisplayName").Split(" ")| Where-Object {$_.contains(".")}}
			[UninstallInfo] @{
				DisplayName      = $_.GetValue("DisplayName") -replace '[^a-z0-9()\\/\., +_-]', ''
				DisplayVersion   = $version
				UninstallString  = $_.GetValue("UninstallString")
				ModifyPath       = $_.GetValue("ModifyPath")
				ProductCodes     = $_.GetValue("ProductCodes")
				InstallLocation  = $_.GetValue("InstallLocation")
				InstallDate      = $installDate
				EstimatedSize    = $_.GetValue("EstimatedSize")
				InnoSetupVersion = $_.GetValue("Inno Setup: Setup Version")
				ChildName        = [io.path]::GetFileName($_.Name)
				FullPath         = $_.Name
				Arch             = if ($_.Name -match "Wow6432Node") {"32-bit"} elseif ($_.Name -match "HKEY_LOCAL_MACHINE" -and $_.Name -notmatch "Wow6432Node") {"64-bit"} else {"Unknown"}
			}
		}
	}
	
	#$Software = Get-RegUninstallInfo
	#$Software | Where-Object {$_.displayName -match "010 Editor"}

	# De-duplicator for the Matching Array
	function Dedup ($MultList){

	# Prime MS Finder
	if ($MultList | Where-Object {$_.DisplayName -match "Microsoft"}){
		if ($MultList | Where-Object {$_.ProductCodes -ne $null}){$Return = $MultList | Where-Object {$_.ProductCodes -ne $null}}
		elseif ($MultList | Where-Object {$_.InstallLocation -ne $null}) {$Return = $MultList | Where-Object {$_.InstallLocation -ne ""}}
		
		$Return.EstimatedSize = ($MultList.EstimatedSize | measure -Maximum).Maximum
	}

	# Find the Program with the Greatest Size
	elseif ($MultList | Where-Object {$_.DisplayName -notmatch "Microsoft"}){
		$MaxSize = ($MultList.EstimatedSize | measure -Maximum).Maximum
		$Return = $MultList | Where-Object {$_.EstimatedSize -eq $MaxSize}
		
		# If there is still more than 2 pick the one with an Install date
		if ($Return.Length -gt "1"){$Return = $Return | Where-Object {$_.InstallDate -ne $Null}}
		
		# Resolve the Architecture if Unknown
		if ($Return.Arch -eq "Unknown"){$Return.Arch = ($MultList.Arch -ne "Unknown")[0]}
	}

	# Multi Date Finder / Fixer
	try{
	foreach ($M in $MultList){
		if ($Return.InstallDate -eq $null){
			$Return.InstallDate = $M.InstallDate
		}
	}} catch {}
	
	return $Return}

	# Path Fixer
	function PathFixer ($String){
		
	# Handle DLL32 but not ClickOnce
	if (($String -match "rundll32") -and ($String -notmatch "dfshim.dll")){
	$Return = $String.Split('"') | Where-Object {$_ -match "C:" -and $_ -notmatch "DLL32"} } else {
	$String = $String -replace '[^a-z0-9(){}\\/\:. +_-]',''
			
	# Find Index of ".exe"
	$Index = $String.IndexOf('.exe') + 4
	$Return = $String.Substring(0,$Index)}
				
	return $Return}
	
	# Correct the Uninstall String (Yes)
	function UnsForm ($List, $FilePath){
	
	# Support Functions
		
		# MSI Formater
		function MSI-Form ($List){
		
		$String = $List.UninstallString
		$Modify = $List.ModifyPath
		$Child = $List.PSChildName
		
			if ($String){ $Temp = $String }
			elseif ($Modify){ $Temp = $Modify}
			else { $Temp = $Child }
		
		$GUID = $Temp | Select-String -Pattern '{[-0-9A-F]+?}' | Select-Object -ExpandProperty Matches | Select-Object -ExpandProperty Value
		$Args = '"/Uninstall ' + $GUID + ' /qn /norestart"'
		$Return = 'Start-Process -FilePath "msiexec.exe" -ArgumentList ' + $Args + ' -wait'
		
		return $Return}
		
		# Inno setup Formater
		function INNO-Form ($Path){
	
		$Args = "/Silent /NoRestart"
		$Return = 'Start-Process -FilePath "' + $Path + '" -ArgumentList "' + $Args + '" -wait'
		
		return $Return}
		
		# Package Cache Formatter
		function PackageCache-Form ($Path){
		
		$Args = "/Uninstall /quiet"
		$Return = 'Start-Process -FilePath "' + $Path + '" -ArgumentList "' + $Args + '" -wait'
		
		return $Return}
		
		# Unknown Formatter
		function Unknown-Form ($String, $FilePath){
		
		# Install Packers
		$NSIS = 'name="Nullsoft.NSIS.exehead"'; $Arg = "/S"
		
		# Parse the Uninstall File
		Get-Content -Path $FilePath -Encoding string | ForEach-Object {
			if ($_ -match $NSIS){
			$Manual = 'Start-Process -FilePath "' + $FilePath + '" -ArgumentList "' + $Arg + '" -wait'}
		}
			
		# Collect Garbage
		[System.GC]::Collect()
		
		if (!$Manual){
		# Path + Args
		# C:\Program Files\Example\Example-Uninstall.exe \Switches Go Here
		# Start-Process -FilePath "C:\Program Files\Example\Example-Uninstall.exe" -ArgumentList "\Switches Go Here" -wait
		
		$Prep = $String -replace '"',''
		$Index = $String.IndexOf('.exe') + 4
		$Path = ($Prep.Substring(0,$Index)).Trim()
		$Args = ($Prep.Substring($Index)).Trim()
		
		$Return = 'Start-Process -FilePath "' + $Path + '" -ArgumentList "' + $Args + '" -wait'} else {$Return = $Manual}
		
		return $Return}
		
		
	# Define Function matching
	if ($List.UninstallString -match "Package Cache"){$Switch = "PackageCache"}
	elseif ($List.InnoSetupVersion -ne ""){$Switch = "INNO"} # Check for INNO Setup
	elseif (($List.UninstallString -match "MsiExec") -or ($List.ModifyPath -match "MsiExec")){$Switch = "MSI"} # Check for MSI Reg Key
	else {$Switch = "Unknown"}
	#else {$Proper = Manual-Form $FilePath} # Manually Parse the File
	
	# Set the Remove Var
	Switch ($Switch) {

		# MSI
		MSI {$Proper = MSI-Form $List}
		
		# INNO
		INNO {$Proper = INNO-Form $FilePath}
		
		# PACKAGE CACHE
		PackageCache {$Proper = PackageCache-Form $FilePath}
		
		# Unknown
		Unknown {$Proper = Unknown-Form $List.UninstallString $FilePath}
	
	}
	
	return $Proper}
	
	# Get the Architecture of the Executable
	function ArcFixer ($Path, $Name){
	
	if (($Name -match "64-bit") -or ($Name -match "64bit")){$Return = "64-bit"} else {	
		$Return = Get-PEArchitecture $Path
	}
	
	return $Return}
	
	# Get the Install Version (From Nothing)
	function VerFixer ($List, $Path){
		
		# Steam Game Version
		if ($List.UninstallString -match "steam://"){
		$Loco = ls $List.InstallLocation | where {$_.extension -eq ".exe"}
		$FilePath = $Loco[0].FullName}
		
		# Other Software
		else {$FilePath = $Path}
		
		# Get the Version from the FilePath
		$Ver = ((gi $FilePath).VersionInfo).FileVersion

		# Cleanup the Version
		if ($Ver.Contains(" ") -and $Ver.Contains(",")){
		$Ver = $Ver.Replace(",",".")
		$Ver = $Ver.Replace(" ","")}
		
	return $Ver}
	
	# Correct the Size Formatting (Yes)
	function SizeForm ($Num){
	
	if (($Num -gt "0") -and ($Num -lt "1000")){
		$Return = [math]::Round($Num, "3").ToString() + " KB"}
	elseif (($Num -gt "1000") -and ($Num -lt "1000000")){
		$Return = [math]::Round(($Num / "1KB"),"3").ToString() + " MB"}
	elseif ($Num -gt "1000000"){
		$Return = [math]::Round(($Num / "1KB" / "1KB"),"3").ToString() + " GB"}
	
	return $Return}
	
	# Get the Correct Size (issue with Microsoft Office Size)
	function SizeFixer ($String, $Location){
	
		# Find Install Folder
		function FoldFinder ($String){
		
		# Program Files
		if (($String -match "Program Files") -and ($String -notlike "*Program Files (x86)*") -and ($String -notmatch "InstallShield")) {$Temp =  $env:ProgramFiles + '\' + $String.Split("\")[2]}
		elseif (($String -match "Program Files") -and ($String -notlike "*Program Files (x86)*") -and ($String -match "InstallShield")) {$Temp =  $env:ProgramFiles + '\InstallShield Installation Information\' + $String.Split("\")[3]}
		
		# Program Files (x86)
		elseif (($String -like "*Program Files (x86)*") -and ($String -notmatch "InstallShield")) {$Temp =  'C:\Program Files (x86)\' + $String.Split("\")[2]}
		elseif (($String -like "*Program Files (x86)*") -and ($String -match "InstallShield")) {$Temp =  'C:\Program Files (x86)\InstallShield Installation Information\' + $String.Split("\")[3]}
		
		# Other
		elseif ($String -like "*ProgramData\Package Cache*"){$Temp = $env:SystemDrive + '\ProgramData\Package Cache\' + $String.split("\")[3]}
		elseif ($String -like "*AppData\Local*" ){ $Temp = $env:userprofile + '\AppData\Local\' + $String.split("\")[5]}

		$Return = $Temp.Trim()
		
		return $Return}
			
	# Make it Work based off the Parent Folder
	if ($Location){$Path = $Location} else {$Path = FoldFinder $String}
	$Sum = (Get-ChildItem $Path -Recurse -Force -ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum / "1KB"
	$Return = SizeForm $Sum
	return $Return}
	
	# Build the Return and call Functions if necessary
	function TableConv ($List){
	
	#if ((($List.UninstallString -ne "") -and ($List.UninstallString -ne $null)) -and ($List.UninstallString -notmatch "InstallShield") -and ($List.UninstallString -notmatch "steam://") -and ($List.UninstallString -notmatch "MsiExec")){
	
	# Temp Vars (with Null Check)
	$Checker = "",$Null,"InstallShield","steam://","MsiExec"
	if ($Checker -notcontains $List.UninstallString){
			$UnsPath = PathFixer $List.UninstallString
	}
		
	# Return Vars
	$Return = @{}
	#$Return.Arch = $List.Arch
	$Return.Name = $List.DisplayName
	$Return.Remove = UnsForm $List $UnsPath
	$Return.Install_Date = $List.InstallDate
	
	if ($List.Arch -ne "Unknown"){
	$Return.Arch = $List.Arch} else {$Return.Arch = ArcFixer $UnsPath $List.DisplayName}
	
	if ($List.DisplayVersion){
	$Return.Install_Version = $List.DisplayVersion} else {$Return.Install_Version = VerFixer $List $UnsPath}
	
	if ($List.EstimatedSize){
	$Return.Size = SizeForm $List.EstimatedSize} else {$Return.Size = SizeFixer $UnsPath $List.InstallLocation}
		
	return $Return}

<# 	# Program String Parser 
	function StringParser($String){
	
	# Extract Special Chars aka + -
	
	return $Sub} #>

# Declare / Populate Variables
$Result = @{}
$Software = Get-RegUninstallInfo

# Parse Program Variable
# - +
<# $Letters = ($Program -replace '[^a-z ]','').Trim()
$Numbers = $Program -replace '[^0-9]',''
$Special = $Program -replace '[a-z0-9]','' #>
#if ($Program.Contains('+'){}

	if ($Software.DisplayName -match $Program){
	[array]$FullList = $Software | Where-Object {$_.displayName -match $Program}
	
		if ($FullList.Count -ne "0"){
		$Result.Status = "Installed"
			if ($FullList.Count -gt "1"){
			$Singler = Dedup $FullList
			$Result += TableConv $Singler
			}
			if ($FullList.Count -eq "1"){
			$Result += TableConv $FullList
			}
		}
	
	} else {$Result.Status = "Not Installed"}
	
return $Result}

export-modulemember -function Install-Check