rule Worm_Loveletter_A_con {
    meta:
        description = "Detects Loveletter"
        author = "Kybero Labs"

    strings:
        $s1 = "Source Code of LOVELETTER.vbs"
        $s2 = "rem  barok -loveletter(vbe) <i hate go to school>"
        $s3 = "rem 			by: spyder  /  ispyder@mail.com  /  @GRAMMERSoft Group  /"

    condition:
        all of them
}
