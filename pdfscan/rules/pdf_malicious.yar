rule PDF_Suspicious_OpenAction_JS
{
    meta:
        severity = "medium"
        description = "PDF contains OpenAction and JavaScript markers"
    strings:
        $pdf = "%PDF-"
        $open = "/OpenAction"
        $js1 = "/JavaScript"
        $js2 = "/JS"
    condition:
        $pdf at 0 and $open and any of ($js*)
}

rule PDF_High_Launch_Embedded
{
    meta:
        severity = "high"
        description = "PDF contains Launch and EmbeddedFile markers"
    strings:
        $pdf = "%PDF-"
        $launch = "/Launch"
        $embedded = "/EmbeddedFile"
    condition:
        $pdf in (0..1024) and $launch and $embedded
}
