from pathlib import Path
import shutil
from tempfile import mkdtemp, mkstemp
from typing import Optional
from unittest import mock, TestCase

from pass_to_keepassxc import Converter


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
        _, filename = mkstemp(dir=self.password_store, suffix=".gpg")

        password = "secret"
        gpg_content = "\n".join([password])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Entry/String")
            self.assertEqual(value_dict["Password"], "secret")

    def test_title_defaults_to_filename(self) -> None:
        _, filename = mkstemp(dir=self.password_store, suffix=".gpg")

        password = ""
        gpg_content = "\n".join([password])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Entry/String")
            self.assertEqual(value_dict["Title"], Path(filename).stem)

    def test_converts_username(self) -> None:
        mkstemp(dir=self.password_store, suffix=".gpg")

        password = ""
        gpg_content = "\n".join([password, "login:username"])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Entry/String")
            self.assertEqual(value_dict["UserName"], "username")

    def test_username_defaults_to_empty(self) -> None:
        mkstemp(dir=self.password_store, suffix=".gpg")

        password = ""
        gpg_content = "\n".join([password])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Entry/String")
            self.assertEqual(value_dict["UserName"], "")

    def test_url_defaults_to_empty(self) -> None:
        mkstemp(dir=self.password_store, suffix=".gpg")

        password = ""
        gpg_content = "\n".join([password])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Entry/String")
            self.assertEqual(value_dict["URL"], "")

    def test_converts_url(self) -> None:
        mkstemp(dir=self.password_store, suffix=".gpg")

        password = ""
        gpg_content = "\n".join([password, "url:www.example.org"])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Entry/String")
            self.assertEqual(value_dict["URL"], "www.example.org")

    def test_converts_notes(self) -> None:
        mkstemp(dir=self.password_store, suffix=".gpg")

        password = ""
        gpg_content = "\n".join([password, "some stuff"])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Entry/String")
            self.assertEqual(value_dict["Notes"], "some stuff")

    def test_whole_record_converted(self) -> None:
        _, filename = mkstemp(dir=self.password_store, suffix=".gpg")

        password = "secret"
        gpg_content = "\n".join(
            [
                password,
                "login:username",
                "url:www.example.org",
                "some stuff",
                "otpauth://totp/ietfuser?secret=NBSWY3DPFQQHO33SNRSAU",
            ]
        )
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Entry/String")
            self.assertEqual(value_dict["Notes"], "some stuff")
            self.assertEqual(
                value_dict["otp"],
                "otpauth://totp/ietfuser?secret=NBSWY3DPFQQHO33SNRSAU",
            )
            self.assertEqual(value_dict["Password"], "secret")
            self.assertEqual(value_dict["Title"], Path(filename).stem)
            self.assertEqual(value_dict["URL"], "www.example.org")
            self.assertEqual(value_dict["UserName"], "username")

    def test_converts_password_in_subdirectory(self) -> None:
        test_dir = mkdtemp(dir=self.password_store)
        mkstemp(dir=test_dir, suffix=".gpg")

        password = "secret"
        gpg_content = "\n".join([password])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Group/Entry/String")
            self.assertEqual(value_dict["Password"], "secret")

    def test_converts_password_in_subsubdirectory(self) -> None:
        test_dir = mkdtemp(dir=self.password_store)
        test_subdir = mkdtemp(dir=test_dir)
        mkstemp(dir=test_subdir, suffix=".gpg")

        password = "secret"
        gpg_content = "\n".join([password])
        self.mock_decode.return_value = gpg_content
        with mock.patch.multiple(
            "pass_to_keepassxc.subprocess", run=self.mock_run
        ):
            value_dict = self._convert_to_dict("./Group/Group/Entry/String")
            self.assertEqual(value_dict["Password"], "secret")

    def _convert_to_dict(self, string_path: str) -> dict[str, Optional[str]]:
        out = Converter().to_xml(Path(self.password_store))

        value_dict: dict[str, Optional[str]] = {}

        for string in out.root.findall(string_path):
            key_element = string.find("Key")
            value_element = string.find("Value")

            assert key_element is not None
            assert value_element is not None

            if key_element.text:
                value_dict[key_element.text] = value_element.text

        return value_dict
