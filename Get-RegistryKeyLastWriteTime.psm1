﻿Function Get-RegistryKeyTimestamp {
    <#
        .SYNOPSIS
            Retrieves the registry key timestamp from a local or remote system.
 
        .DESCRIPTION
            Retrieves the registry key timestamp from a local or remote system.
 
        .PARAMETER RegistryKey
            Registry key object that can be passed into function.
 
        .PARAMETER SubKey
            The subkey path to view timestamp.
 
        .PARAMETER RegistryHive
            The registry hive that you will connect to.
 
            Accepted Values:
            ClassesRoot
            CurrentUser
            LocalMachine
            Users
            PerformanceData
            CurrentConfig
            DynData
 
        .NOTES
            Name: Get-RegistryKeyTimestamp
            Author: Boe Prox
            Version History:
                1.0 -- Boe Prox 17 Dec 2014
                    -Initial Build
 
        .EXAMPLE
            $RegistryKey = Get-Item "HKLM:\System\CurrentControlSet\Control\Lsa"
            $RegistryKey | Get-RegistryKeyTimestamp | Format-List
 
            FullName      : HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
            Name          : Lsa
            LastWriteTime : 12/16/2014 10:16:35 PM
 
            Description
            -----------
            Displays the lastwritetime timestamp for the Lsa registry key.
 
        .EXAMPLE
            Get-RegistryKeyTimestamp -Computername Server1 -RegistryHive LocalMachine -SubKey 'System\CurrentControlSet\Control\Lsa' |
            Format-List
 
            FullName      : HKEY_LOCAL_MACHINE\System\CurrentControlSet\Control\Lsa
            Name          : Lsa
            LastWriteTime : 12/17/2014 6:46:08 AM
 
            Description
            -----------
            Displays the lastwritetime timestamp for the Lsa registry key of the remote system.
 
        .INPUTS
            System.String
            Microsoft.Win32.RegistryKey
 
        .OUTPUTS
            Microsoft.Registry.Timestamp
    #>
    [OutputType('Microsoft.Registry.Timestamp')]
    [cmdletbinding(
        DefaultParameterSetName = 'ByValue'
    )]
    Param (
        [parameter(ValueFromPipeline=$True, ParameterSetName='ByValue')]
        [Microsoft.Win32.RegistryKey]$RegistryKey,
        [parameter(ParameterSetName='ByPath')]
        [string]$SubKey,
        [parameter(ParameterSetName='ByPath')]
        [Microsoft.Win32.RegistryHive]$RegistryHive,
        [parameter(ParameterSetName='ByPath')]
        [string]$Computername
    )
    Begin {
        #region Create Win32 API Object
        Try {
            [void][advapi32]
        } Catch {
            #region Module Builder
            $Domain = [AppDomain]::CurrentDomain
            $DynAssembly = New-Object System.Reflection.AssemblyName('RegAssembly')
            $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run) # Only run in memory
            $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('RegistryTimeStampModule', $False)
            #endregion Module Builder
 
            #region DllImport
            $TypeBuilder = $ModuleBuilder.DefineType('advapi32', 'Public, Class')
 
            #region RegQueryInfoKey Method
            $PInvokeMethod = $TypeBuilder.DefineMethod(
                'RegQueryInfoKey', #Method Name
                [Reflection.MethodAttributes] 'PrivateScope, Public, Static, HideBySig, PinvokeImpl', #Method Attributes
                [IntPtr], #Method Return Type
                [Type[]] @(
                    [Microsoft.Win32.SafeHandles.SafeRegistryHandle], #Registry Handle
                    [System.Text.StringBuilder], #Class Name
                    [UInt32 ].MakeByRefType(),  #Class Length
                    [UInt32], #Reserved
                    [UInt32 ].MakeByRefType(), #Subkey Count
                    [UInt32 ].MakeByRefType(), #Max Subkey Name Length
                    [UInt32 ].MakeByRefType(), #Max Class Length
                    [UInt32 ].MakeByRefType(), #Value Count
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Max Value Name Length
                    [UInt32 ].MakeByRefType(), #Security Descriptor Size           
                    [long].MakeByRefType() #LastWriteTime
                ) #Method Parameters
            )
 
            $DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
            $FieldArray = [Reflection.FieldInfo[]] @(       
                [Runtime.InteropServices.DllImportAttribute].GetField('EntryPoint'),
                [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
            )
 
            $FieldValueArray = [Object[]] @(
                'RegQueryInfoKey', #CASE SENSITIVE!!
                $True
            )
 
            $SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder(
                $DllImportConstructor,
                @('advapi32.dll'),
                $FieldArray,
                $FieldValueArray
            )
 
            $PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
            #endregion RegQueryInfoKey Method
 
            [void]$TypeBuilder.CreateType()
            #endregion DllImport
        }
        #endregion Create Win32 API object
    }
    Process {
        #region Constant Variables
        $ClassLength = 255
        [long]$TimeStamp = $null
        #endregion Constant Variables
 
        #region Registry Key Data
        If ($PSCmdlet.ParameterSetName -eq 'ByPath') {
            #Get registry key data
            $RegistryKey = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey($RegistryHive, $Computername).OpenSubKey($SubKey)
            If ($RegistryKey -isnot [Microsoft.Win32.RegistryKey]) {
                Throw "Cannot open or locate $SubKey on $Computername"
            }
        }
 
        $ClassName = New-Object System.Text.StringBuilder $RegistryKey.Name
        $RegistryHandle = $RegistryKey.Handle
        #endregion Registry Key Data
 
        #region Retrieve timestamp
        $Return = [advapi32]::RegQueryInfoKey(
            $RegistryHandle,
            $ClassName,
            [ref]$ClassLength,
            $Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$Null,
            [ref]$TimeStamp
        )
        Switch ($Return) {
            0 {
               #Convert High/Low date to DateTime Object
                $LastWriteTime = [datetime]::FromFileTime($TimeStamp)
 
                #Return object
                $Object = [pscustomobject]@{
                    FullName = $RegistryKey.Name
                    Name = $RegistryKey.Name -replace '.*\\(.*)','$1'
                    LastWriteTime = $LastWriteTime
                }
                $Object.pstypenames.insert(0,'Microsoft.Registry.Timestamp')
                $Object
            }
            122 {
                Throw "ERROR_INSUFFICIENT_BUFFER (0x7a)"
            }
            Default {
                Throw "Error ($return) occurred"
            }
        }
        #endregion Retrieve timestamp
    }
}

export-modulemember -function Get-RegistryKeyTimestamp