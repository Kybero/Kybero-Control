rule Trojan_Agent_A_con {
    meta:
        description = "Detects trojan"
        author = "Kybero Labs"

    strings:
        $s1 = "ADAMANDPRASHANTAREAWESOME"
        $s2 = "C:\\ping_pong\\win_client\\Release\\win_client.pdb"

    condition:
        all of them
}

rule Trojan_Agent_B_con {
    meta:
        description = "Detects trojan"
        author = "Kybero Labs"

    strings:
        $s1 = "C:\Users\Ďŕâĺë\Desktop\test.pb"

    condition:
        all of them
}
