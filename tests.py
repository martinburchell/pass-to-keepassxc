from pathlib import Path
import shutil
from tempfile import mkdtemp, mkstemp
from typing import Optional
from unittest import mock, TestCase

from pass_to_keepassxc import convert_to_xml


class ConvertToXmlTests(TestCase):
    def setUp(self) -> None:
        self.password_store = mkdtemp()
        self.mock_decode = mock.Mock()
        mock_stdout = mock.Mock(decode=self.mock_decode)
        mock_completed_process = mock.Mock(stdout=mock_stdout)
        self.mock_run = mock.Mock(return_value=mock_completed_process)

    def tearDown(self) -> None:
        shutil.rmtree(self.password_store)

    def test_converts_password(self) -> None:
        test_dir = mkdtemp(dir=self.password_store)
        mkstemp(dir=test_dir, suffix=".gpg")

        password = "secret"
        gpg_content = "\n".join([password])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):

            value_dict = self._convert_to_dict()
            self.assertEqual(value_dict["Password"], "secret")

    def test_defaults_username_to_filename(self) -> None:
        test_dir = mkdtemp(dir=self.password_store)
        _, filename = mkstemp(dir=test_dir, suffix=".gpg")

        password = ""
        gpg_content = "\n".join([password])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):

            value_dict = self._convert_to_dict()
            self.assertEqual(value_dict["UserName"], Path(filename).stem)

    def test_converts_username(self) -> None:
        test_dir = mkdtemp(dir=self.password_store)
        mkstemp(dir=test_dir, suffix=".gpg")

        password = ""
        gpg_content = "\n".join([password, "login:username"])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):

            value_dict = self._convert_to_dict()
            self.assertEqual(value_dict["UserName"], "username")

    def _convert_to_dict(self) -> dict[str, Optional[str]]:
        out = convert_to_xml(Path(self.password_store))

        value_dict: dict[str, Optional[str]] = {}

        for string in out.root.findall(".//String"):
            key_element = string.find("Key")
            value_element = string.find("Value")

            assert key_element is not None
            assert value_element is not None

            if key_element.text:
                value_dict[key_element.text] = value_element.text

        return value_dict
