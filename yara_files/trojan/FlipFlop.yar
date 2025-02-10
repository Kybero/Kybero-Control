rule Trojan_FlipFlop_A_con {
   meta:
      threat_name = "Trojan/FlipFlop.A!con"
      author = "threatintel@volexity.com"
      date = "2021-05-25"
      description = "A loader for the CobaltStrike malware family, which ultimately takes the first and second bytes of an embedded file, and flips them prior to executing the resulting payload."
      hash = "ee42ddacbd202008bcc1312e548e1d9ac670dd3d86c999606a3a01d464a2a330"
      reference = "https://www.volexity.com/blog/2021/05/27/suspected-apt29-operation-launches-election-fraud-themed-phishing-campaigns/"
      id = "58696a6f-55a9-5212-9372-a539cc327e6b"
   strings:
      $s1 = "irnjadle"
      $s2 = "BADCFEHGJILKNMPORQTSVUXWZY"
      $s3 = "iMrcsofo taBesC yrtpgoarhpciP orived r1v0."
   condition:
      all of ($s*)
}
