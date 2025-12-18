# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# pyre-strict

from CodeShield.insecure_code_detector.languages import Language
from .insecure_code_detector_test import InsecureCodeDetectorTest


PHP_TEST_CASES = [
    ("hello world", 0),
    ("this is test ", 1),
    # Test cases for API key detection patterns (using clearly fake values)
    ("this is test ", 1),
    ("this is test ", 1),
    ("this is test ", 1),
    ("this is test ", 1),
    ("this is test ", 1),
    ("this is test ", 1),
    ("this is test ", 1),
    ("this is test ", 1),
    # PHP insecure patterns
    ("shell_exec($_GET['command'])", 2),
    ("mysql_query($_POST['query'])", 1),
    ("echo($_GET['message'])", 1),
    ("ini_set('display_errors', 'on')", 1),
    ("md5($input)", 1),
    ("exec($command)", 1),
    ("set_cookie($_POST['query'])", 1),
    ("require($_SESSION['file'])", 1),
    ("file_get_contents($_GET['url'])", 2),
    ("password_hash($password, PASSWORD_DEFAULT)", 1),
    ("die($_GET['message'])", 1),
    ("include($_SESSION['file'])", 1),
    ("chmod($_GET['var'])", 1),
    ("curl_exec($_GET['command'])", 2),
    ("header('Location: ' . $_GET['url'])", 1),
    ("move_uploaded_file($tmp_name, 'uploads/file.exe')", 1),
    ("update($_SESSION['data'])", 1),
    ("mt_rand($a)", 1),
    ("simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOENT)", 1),
]


class TestPHPInsecureCodeDetector(InsecureCodeDetectorTest):
    async def test_php_regex_patterns(self) -> None:
        await self.run_regex_tests(Language.PHP, PHP_TEST_CASES)
