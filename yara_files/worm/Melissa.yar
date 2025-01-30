rule Worm_Melissa_A_con {
    meta:
        threat_name = "Worm/Melissa.A!con"
        description = "Detects Melissa"
        author = "Kybero Labs"

    strings:
        $s1 = "Twenty-two points, plus triple-word-score, plus fifty points for using all my letters. Game's over. I'm outta here."
        $s2 = "Melissa written by Kwyjibo"
        $s3 = "Here is that document you asked for ... don't show anyone else ;-)"

    condition:
        all of them
}
