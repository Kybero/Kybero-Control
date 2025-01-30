rule Trojan_JSRedirector_A_con {
    meta:
        description = "Detects JavaScript code creating functions to redirect links onto a malicious site"
        author = "Kybero Labs"

    strings:
        $s1 = "function mylink() {"
        $s2 = "seoref=\"+encodeURIComponent(document.referrer)+ \"&parameter=$keyword&se=$se&ur=1&HTTP_REFERER=\"+encodeURIComponent(document.URL)+\"&default_keyword="
        $s3 = "<a href=\"#\" onClick=\"mylink()\">"

    condition:
        all of them
}

rule Trojan_JSRedirector_B_con {
    meta:
        description = "Detects obfuscated JavaScript redirector"
        author = "Kybero Labs"

    strings:
        $obf_function = /function\s+[a-zA-Z0-9_]{3,8}\(.*\)\{var\s+[a-zA-Z0-9_]{3,8},[a-zA-Z0-9_]{3,8},[a-zA-Z0-9_]{3,8},[a-zA-Z0-9_]{3,8}/ nocase
        $obf_eval = /eval\(unescape\("%[0-9A-Fa-f]{2}/ nocase
        $iframe_inject = /document\.write\(.*iframe.*src=/ nocase
        $small_iframe = /<iframe\s+[^>]*width=["']?0["']?\s+height=["']?0["']?/ nocase

    condition:
        (
            $obf_function and $obf_eval and ($iframe_inject or $small_iframe)
        )
}

rule Trojan_JSRedirector_C_con {
    meta:
        description = "Detects JavaScript code loading scripts from a known malicious domain"
        author = "Kybero Labs"

    strings:
        $s1 = "<script src=\"http://"
        $s2 = ".rr.nu/"

    condition:
        all of them
}

rule Trojan_JSRedirector_D_con {
    meta:
        description = "Detects generic JavaScript redirector"
        author = "Kybero Labs"

    strings:
        $s1 = "<script language='javascript'>document.write(unescape("

    condition:
        all of them
}
