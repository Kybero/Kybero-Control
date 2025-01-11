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
