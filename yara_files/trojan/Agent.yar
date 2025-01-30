rule Trojan_Agent_A_con {
    meta:
        description = "Detects trojan"
        author = "Kybero Labs"

    strings:
        $s1 = "ADAMANDPRASHANTAREAWESOME"
        $s2 = "C:\\ping_pong\\win_client\\Release\\win_client.pdb"

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Trojan_Agent_B_con {
    meta:
        description = "Detects trojan"
        author = "Kybero Labs"

    strings:
        $s1 = "C:\\Users\\Ďŕâĺë\\Desktop\\test.pb"

    condition:
        uint16(0) == 0x5a4d and all of them
}


rule Trojan_Agent_C_con {
    meta:
        description = "Detects trojan"
        author = "Kybero Labs"

    strings:
        $s1 = "M:\\src\\04F\\_SHW_CF_181213\\SWH_DLL_01\\HookDll\\Release\\HookDll.pdb"

    condition:
        uint16(0) == 0x5a4d and all of them
}

rule Trojan_Agent_D_con {
   meta:
      description = "Unknown malware mentioned by Cylance"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth"
   strings:
      $s1 = "Flyingbird Technology Limited" ascii
      $s2 = "Neoact Co., Ltd." ascii
      $s3 = "EMG Technology Limited" ascii
      $s4 = "Zemi Interactive Co., Ltd" ascii
      $s5 = "337 Technology Limited" ascii
      $s6 = "Runewaker Entertainment0" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 3000KB and 1 of them )
}
