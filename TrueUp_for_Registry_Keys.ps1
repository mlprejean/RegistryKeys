# True-up for Registry Keys
# October 22 2019
# M.Prejean

## This script is created to run within Azure DSC ##
# The purpose of this script is to modify or add registry keys

Configuration xRegistryResource_True_Up_OCT22_RegKeys
{

    #No imput Parameters because these are set keys
    #But will ask if you want to overwrite existing 
    [CmdletBinding()]
    param
    (
#        [Parameter(Mandatory = $true)]
#        [System.String]
#        $KeyPath,
#
#        [Parameter(Mandatory = $true)]
#        [System.String]
#        $Path,
#
#        [Parameter(Mandatory = $true)]
#        [AllowEmptyString()]
#        [System.String]
#        $KeyName,
#        
#        [Parameter(Mandatory = $true)]
#        [AllowEmptyString()]
#        [System.String]
#        $ValueName,
#
#        [Parameter()]
#        [System.String]
#        $ValueData,
#
#        [Parameter()]
#        [ValidateSet('String', 'Binary', 'DWord', 'QWord', 'MultiString', 'ExpandString')]
#        [System.String]
#        $ValueType


        [Parameter()]
        [System.Boolean]
        $OverwriteExisting

    )

    Import-DscResource -ModuleName 'xPSDesiredStateConfiguration'

    Node localhost
    {

        ## REG KEY 
        #  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -name " FeatureSettingsOverride " -value "72" -PropertyType DWORD -Force
        #  Not a new key just an edit
    
        xRegistry 'AddOrModifyValue1'
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            Ensure    = 'Present'
            ValueName = 'FeatureSettingsOverride'
            ValueType = 'DWord'
            ValueData = '72'
            Force     = $OverwriteExisting
        }

        ## REG KEY 
        #  New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -name " FeatureSettingsOverrideMask" -value "3" -PropertyType DWORD -Force
        #  Not a new key just an edit

        xRegistry 'AddOrModifyValue2'
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
            Ensure    = 'Present'
            ValueName = 'FeatureSettingsOverrideMask'
            ValueType = 'DWord'
            ValueData = '3'
            Force     = $OverwriteExisting
        }
        
        ## REG KEY 
        #  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" -name " iexplore.exe" -value "1" -PropertyType DWORD -Force
        #  A new key 

         xRegistry 'AddKey3'
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl'
            Ensure    = 'Present'
            ValueName = 'FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX'
        }
        xRegistry 'AddOrModifyValue3'
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX'
            Ensure    = 'Present'
            ValueName = 'iexplore.exe'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $OverwriteExisting
        }

        ## REG KEY 
        #  New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX" -name " iexplore.exe" -value "1" -PropertyType DWORD -Force
        #  A new key 

         xRegistry 'AddKey4'
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl'
            Ensure    = 'Present'
            ValueName = 'FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX'
        }
        xRegistry 'AddOrModifyValue4'
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ENABLE_PRINT_INFO_DISCLOSURE_FIX'
            Ensure    = 'Present'
            ValueName = 'iexplore.exe'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $OverwriteExisting
        }

        ## REG KEY 
        #  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -name " iexplore.exe" -value "1" -PropertyType DWORD -Force
        #  A new key 

         xRegistry 'AddKey5'
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl'
            Ensure    = 'Present'
            ValueName = 'FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING'
        }
        xRegistry 'AddOrModifyValue5'
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING'
            Ensure    = 'Present'
            ValueName = 'iexplore.exe'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $OverwriteExisting
        }

        ## REG KEY 
        #  New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING" -name " iexplore.exe" -value "1" -PropertyType DWORD -Force
        #  A new key 

         xRegistry 'AddKey6'
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl'
            Ensure    = 'Present'
            ValueName = 'FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING'
        }
        xRegistry 'AddOrModifyValue6'
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Internet Explorer\Main\FeatureControl\FEATURE_ALLOW_USER32_EXCEPTION_HANDLER_HARDENING'
            Ensure    = 'Present'
            ValueName = 'iexplore.exe'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $OverwriteExisting
        }

        ## REG KEY 
        # New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\CredSSP\Parameters" -name " AllowEncryptionOracle" -value "1" -PropertyType DWORD -Force
        #  A new key 

         xRegistry 'AddKey7'
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\CredSSP'
            Ensure    = 'Present'
            ValueName = 'Parameters'
        }
        xRegistry 'AddOrModifyValue7'
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\system\CredSSP\Parameters'
            Ensure    = 'Present'
            ValueName = 'AllowEncryptionOracle'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $OverwriteExisting
        }

        
        ## REG KEY 
        # New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system\CredSSP\Parameters" -name " AllowEncryptionOracle" -value "1" -PropertyType DWORD -Force
        #  A new key 

         xRegistry 'AddKey8'
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system\CredSSP'
            Ensure    = 'Present'
            ValueName = 'Parameters'
        }
        xRegistry 'AddOrModifyValue8'
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\policies\system\CredSSP\Parameters'
            Ensure    = 'Present'
            ValueName = 'AllowEncryptionOracle'
            ValueType = 'DWord'
            ValueData = '1'
            Force     = $OverwriteExisting
        }
       
        ## REG KEY 
        #  New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -name " DefaultSecureProtocols" -value "2560" -PropertyType DWORD -Force
        #  Not a new key just an edit

        xRegistry 'AddOrModifyValue9'
        {
            Key       = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            Ensure    = 'Present'
            ValueName = 'DefaultSecureProtocols'
            ValueType = 'DWord'
            ValueData = '2560'
            Force     = $OverwriteExisting
        }

            
        ## REG KEY 
        # New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp" -name " DefaultSecureProtocols" -value "2560" -PropertyType DWORD -Force
        #  Not a new key just an edit

        xRegistry 'AddOrModifyValue10'
        {
            Key       = 'HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Internet Settings\WinHttp'
            Ensure    = 'Present'
            ValueName = 'DefaultSecureProtocols'
            ValueType = 'DWord'
            ValueData = '2560'
            Force     = $OverwriteExisting
        }

        ## REG KEY 
        # New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest" -name " UseLogonCredential" -value "0" -PropertyType DWORD -Force
        #  Not a new key just an edit

        xRegistry 'AddOrModifyValue11'
        {
            Key       = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\Wdigest'
            Ensure    = 'Present'
            ValueName = 'UseLogonCredential'
            ValueType = 'DWord'
            ValueData = '0'
            Force     = $OverwriteExisting
        }
        ## Keys as of OCT 23 2019 ##
    }
}
