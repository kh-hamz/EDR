rule Reverse_Shell_Script_Pattern
{
    meta:
        description = "Common reverse-shell one-liner patterns"
        attack_technique = "T1059"
    strings:
        $nc_e = "-e /bin/sh"
        $bash_i = "bash -i"
        $dev_tcp = "/dev/tcp/"
        $mkfifo = "mkfifo"
    condition:
        any of them
}
