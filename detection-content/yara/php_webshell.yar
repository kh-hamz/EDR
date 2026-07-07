rule Simple_PHP_Webshell
{
    meta:
        description = "Common PHP webshell primitives"
        attack_technique = "T1505.003"
    strings:
        $eval_b64 = "eval(base64_decode("
        $system_get = "system($_GET["
        $passthru_get = "passthru($_GET["
    condition:
        any of them
}
