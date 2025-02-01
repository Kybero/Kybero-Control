rule Ransom_Rensenware_A_con {
    meta:
        threat_name = "Ransom/Rensenware.A!con"
        description = "Detects Rensenware"
        author = "Kybero Labs"

    strings:
        $s1 = "Minamitsu \"The Captain\" Murasa encrypted your precious data like documents, musics, pictures, and some kinda project files. it can't be recovered without this application because they are encrypted with highly strong encryption algorithm, using random key."
        $s2 = "That's easy. You just play TH12 ~ Undefined Fantastic Object and score over 0.2 billion in LUNATIC level. this application will detect TH12 process and score automatically. DO NOT TRY CHEATING OR TEMRMINATE THIS APPLICATION IF YOU DON'T WANT TO BLOW UP THE ENCRYPTION KEY!"
        $s3 = "C:\\Users\\mkang\\Documents\\Visual Studio 2017\\Projects\\renseiWare\\rensenWare\\obj\\Release\\rensenWare.pdb"

    condition:
        all of them
}
