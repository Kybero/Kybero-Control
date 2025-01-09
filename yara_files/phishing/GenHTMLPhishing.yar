rule Susp_HTMLPhishing_Generic {
    meta:
        description = "Detects HTML phishing based on suspicious commands"
        author = "Kybero Labs"

    strings:
        $h = "doctype html" ascii nocase

        $a1 = $a1 = /dataType:\s*'JSON',\s*url:\s*'[^']*',\s*type:\s*'POST',\s*data:\s*\{\s*email:\s*email,\s*password:\s*password,\s*\}/

    condition:
        $h and $a1
}
