rule Backdoor_Nitol_A_con {
    meta:
        threat_name = "Backdoor/Nitol.A!con"
        author = "ditekSHen"
        description = "Detects Nitol backdoor"
    strings:
        $s1 = "%$#@!.aspGET ^&*().htmlGET" ascii
        $s2 = "Applications\\iexplore.exe\\shell\\open\\command" fullword ascii
        $s3 = "taskkill /f /im rundll32.exe" fullword ascii
        $s4 = "\\Tencent\\Users\\*.*" fullword ascii
        $s5 = "[Pause Break]" fullword ascii
        $s6 = ":]%d-%d-%d  %d:%d:%d" fullword ascii
        $s7 = "GET %s HTTP/1.1" fullword ascii
        $s8 = "GET %s%s HTTP/1.1" fullword ascii
        $s9 = "Accept-Language: zh-cn" fullword ascii
        $s10 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows 5.1)" fullword ascii
        $s11 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
        $s12 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
        $w1 = ".aspGET" ascii
        $w2 = ".htmGET" ascii
        $w3 = ".htmlGET" ascii
        $domain = "www.xy999.com" fullword ascii
        $v2_1 = "loglass" fullword ascii
        $v2_2 = "rlehgs" fullword ascii
        $v2_3 = "eherrali" fullword ascii
        $v2_4 = "agesrlu" fullword ascii
        $v2_5 = "lepejagas" fullword ascii
    condition:
        uint16(0) == 0x5a4d and (5 of ($s*) or (all of ($v2*)) or ($domain and 3 of them) or (#w1 > 2 and #w2 > 2 and #w3 > 2 and 3 of ($s*)))
}

rule Backdoor_Nitol_B_con {
   meta:
      threat_name = "Backdoor/Nitol.B!con"
      description = "Detects malware backdoor Nitol - file wyawou.exe - Attention: this rule also matches on Upatre Downloader"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://goo.gl/OOB3mH"
      date = "2017-06-04"
      modified = "2023-01-07"
      hash1 = "cba19d228abf31ec8afab7330df3c9da60cd4dae376552b503aea6d7feff9946"
      id = "7dd26868-59e0-51a1-b12a-3b69d6246ff5"
   strings:
      $x1 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.00; Windows NT %d.0; MyIE 3.01)" fullword ascii
      $x2 = "User-Agent:Mozilla/4.0 (compatible; MSIE %d.0; Windows NT %d.1; SV1)" fullword ascii
      $x3 = "TCPConnectFloodThread.target = %s" fullword ascii

      $s1 = "\\Program Files\\Internet Explorer\\iexplore.exe" ascii
      $s2 = "%c%c%c%c%c%c.exe" fullword ascii
      $s3 = "GET %s%s HTTP/1.1" fullword ascii
      $s4 = "CCAttack.target = %s" fullword ascii
      $s5 = "Accept-Language: zh-cn" fullword ascii
      $s6 = "jdfwkey" fullword ascii
      $s7 = "hackqz.f3322.org:8880" fullword ascii
   condition:
      ( uint16(0) == 0x5a4d and filesize < 200KB and ( 1 of ($x*) or 5 of ($s*) ) ) or ( all of them )
}
