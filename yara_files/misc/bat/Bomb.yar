rule BAT_Bomb_A_con {
    meta:
        threat_name = "BAT/Bomb.A!con"
        description = "Detects batch files with self-replication behavior"
        author = "Kybero Labs"

    strings:
        $s1 = /set\s+x=%random%/ nocase
        $s2 = /type\s+%0\s+>>\s+%x%.bat/ nocase
        $s3 = /start\s+%x%.bat/ nocase
        $s4 = /goto\s*:/ nocase

    condition:
        all of ($s*)
}
