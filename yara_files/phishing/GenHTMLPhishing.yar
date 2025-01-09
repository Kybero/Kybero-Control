rule Susp_HTMLPhishing_Generic {
    meta:
        description = "Detects HTML phishing based on suspicious commands"
        author = "Kybero Labs"

    strings:
        $p = "<!doctype html>"

        $a1 = /dataType:\s*'JSON',\s*url:\s*'.*?',\s*type:\s*'POST',\s*data:\s*\{\s*email:\s*email,\s*password:\s*password,\s*\}/

    condition:
        $p and 1 of ($a*)
}

rule HTMLPhishing_Generic_A {
    meta:
        description = "Detects HTML phishing based on risky domain connections"
        author = "Kybero Labs"

    strings:
        $p = "<!doctype html>"

        $s1 = "https://centrocomercialparana.com.ar/"

    condition:
        $p and 1 of ($s*)
}
