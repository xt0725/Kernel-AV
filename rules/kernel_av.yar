rule KernelAV_EICAR_Test_File
{
    meta:
        description = "Standard harmless EICAR antivirus test file"
        severity = 100
        family = "test"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" ascii
    condition:
        $eicar
}

rule KernelAV_Suspicious_PowerShell_Loader
{
    meta:
        description = "PowerShell script combines obfuscation and in-memory loading traits"
        severity = 75
        family = "generic-powershell-loader"
    strings:
        $ps = "powershell" ascii wide nocase
        $b64 = "FromBase64String" ascii wide nocase
        $mem1 = "VirtualAlloc" ascii wide nocase
        $mem2 = "Reflection.Assembly" ascii wide nocase
        $exec1 = "Invoke-Expression" ascii wide nocase
        $exec2 = "IEX" ascii wide nocase fullword
    condition:
        $ps and $b64 and 1 of ($mem*) and 1 of ($exec*)
}

rule KernelAV_Generic_Ransomware_Note
{
    meta:
        description = "Text contains several common ransomware-note concepts"
        severity = 65
        family = "generic-ransom-note"
    strings:
        $a = "your files have been encrypted" ascii wide nocase
        $b = "decrypt your files" ascii wide nocase
        $c = "bitcoin" ascii wide nocase
        $d = "recovery key" ascii wide nocase
        $e = "payment" ascii wide nocase
    condition:
        filesize < 2MB and 3 of them
}

