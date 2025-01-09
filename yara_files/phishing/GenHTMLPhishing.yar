rule Susp_HTMLPhishing_Generic {
    meta:
        description = "Detects HTML phishing based on suspicious commands"
        author = "Kybero Labs"

    strings:
        $h = "doctype html" ascii nocase

        $a1 = /dataType:\s*'JSON',\s*url:\s*'.*?',\s*type:\s*'POST',\s*data:\s*\{\s*email:\s*email,\s*password:\s*password,\s*\}/

    condition:
        $h and $a1
}

rule HTMLPhishing_Generic_A {
    meta:
        description = "Detects HTML phishing based on risky domain connections"
        author = "Kybero Labs"

    strings:
        $h = "doctype html" ascii nocase

        $s1 = "https://centrocomercialparana.com.ar/"

    condition:
        $h and $s1
}
