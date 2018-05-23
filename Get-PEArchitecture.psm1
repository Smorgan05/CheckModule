function Get-PEArchitecture
{

 <#
        .SYNOPSIS
            Retrieves the bittness of a portable executable based off the Portable Executable Header Information (PE Header)

			This code is taken from the Invoke-DllInjection.ps1 script of EmpireProject / Empire: line 136.  It has undergone minor modifications.  However, it is only used for the purpose of obtaining the bittness of a Portable Executable and does not do anything malicious.  This is reflected in the fact that it reads select bytes of a file to determine the bittness based off the PE Header information and other select areas of the file inputted into this function.
 
 
        .DESCRIPTION
            Retrieves the bittness (aka 32-bit or 64-bit for example) information for a Portable Executable
 
        .PARAMETER Path
            String of Path to Portable Executable.

        .NOTES
            Name: Get-PEArchitecture
            Author: Matthew Graeber (@mattifestation)
			Copyright: Copyright 2016 Matthew Graeber
			License: BSD 3-Clause (as seen on EmpireProject)
			License Info: https://opensource.org/licenses/BSD-3-Clause
 
        .EXAMPLE
            Get-PEArchitecture -Path "$($Env:SystemRoot)\System32\kernel32.dll"
			
			Original Output:
			X64
 
			Current Output with modifications:
			64-bit
 
            Description
            -----------
            Displays the bittness of the System32 \ Kernel32.dll file.
		
		.EXAMPLE
			Get-PEArchitecture -Path "$($Env:SystemRoot)\SysWow64\kernel32.dll"	
		
			Original Output:
			X86
			
			Current Output with modifications:
			32-bit
			
			Description
            -----------
            Displays the bittness of the SysWow64 \ Kernel32.dll file.
 
        .INPUTS
            System.String
 
        .OUTPUTS
            System.String / Write-Output
    #>

    Param
    (
        [Parameter(Mandatory=$True,Position=1)][String]$Path
    )

    # Parse PE header to see if binary was compiled 32 or 64-bit
    $FileStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)

    [Byte[]] $MZHeader = New-Object Byte[](2)
    $FileStream.Read($MZHeader,0,2) | Out-Null

    $Header = [System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)
    if ($Header -ne 'MZ')
    {
        $FileStream.Close()
        Throw 'Invalid PE header.'
    }

    # Seek to 0x3c - IMAGE_DOS_HEADER.e_lfanew (i.e. Offset to PE Header)
    $FileStream.Seek(0x3c, [System.IO.SeekOrigin]::Begin) | Out-Null

    [Byte[]] $lfanew = New-Object Byte[](4)

    # Read offset to the PE Header (will be read in reverse)
    $FileStream.Read($lfanew,0,4) | Out-Null
    $PEOffset = [Int] ('0x{0}' -f (( $lfanew[-1..-4] | % { $_.ToString('X2') } ) -join ''))

    # Seek to IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE
    $FileStream.Seek($PEOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
    [Byte[]] $IMAGE_FILE_MACHINE = New-Object Byte[](2)

    # Read compiled architecture
    $FileStream.Read($IMAGE_FILE_MACHINE,0,2) | Out-Null
    $Architecture = '{0}' -f (( $IMAGE_FILE_MACHINE[-1..-2] | % { $_.ToString('X2') } ) -join '')
    $FileStream.Close()

    if (($Architecture -ne '014C') -and ($Architecture -ne '8664'))
    {
        Throw 'Invalid PE header or unsupported architecture.'
    }

    if ($Architecture -eq '014C')
    {
        #Write-Output 'X86'
		Write-Output '32-bit'
    }
    elseif ($Architecture -eq '8664')
    {
        #Write-Output 'X64'
        Write-Output '64-bit'
    }
    else
    {
        Write-Output 'OTHER'
    }
}
export-modulemember -function Get-PEArchitecture