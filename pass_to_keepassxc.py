#!/usr/bin/env python

# Turn a pass (https://www.passwordstore.org/) repository into an XML file
# to import into KeePassXC. XML is dumped into stdout.
#
# Usage:
# python3 pass-to-keepassxc.py <password store directory>
#
# Example:
#
# Typically, pass's password store directory is `~/.password-store`.
#
# $ python3 pass-to-keepassxc.py ~/.password-store > deleteme.xml
# $ keepassxc-cli import deleteme.xml MyKeepassXCPasswords.kbdx
# $ rm deleteme.xml
#
# Then go and configure additional settings in the KeePassXC GUI or CLI.

import argparse
from xml.etree import ElementTree as ET
import sys
import subprocess
from pathlib import Path
from typing import Any, Optional, Tuple


class KeepassXCEntry:
    """
    Generate XML entries like this:
        <Entry>
                <String>
                        <Key>Notes</Key>
                        <Value ProtectInMemory="True"></Value>
                </String>
                <String>
                        <Key>Password</Key>
                        <Value ProtectInMemory="True"></Value>
                </String>
                <String>
                        <Key>Title</Key>
                        <Value></Value>
                </String>
                <String>
                        <Key>URL</Key>
                        <Value></Value>
                </String>
                <String>
                        <Key>UserName</Key>
                        <Value></Value>
                </String>
                <String>
                        <Key>otp</Key>
                        <Value ProtectInMemory="True"></Value>
                </String>
                <AutoType>
                        <Enabled>True</Enabled>
                        <DataTransferObfuscation>0</DataTransferObfuscation>
                        <DefaultSequence/>
                </AutoType>
                <History/>
        </Entry>
    """

    def __init__(
        self,
        username: str,
        password: str,
        url: str,
        title: str,
        notes: str = "",
        totp: Optional[str] = None,
    ) -> None:
        self.root = ET.Element("Entry")
        self.add_string_field("Notes", notes)
        self.add_string_field("UserName", username)
        self.add_string_field("Password", password)
        self.add_string_field("URL", url)
        self.add_string_field("Title", title)
        self.add_string_field("otp", totp or "")
        self.add_auto_type()

    def __str__(self) -> Any:
        return ET.tostring(self.root, encoding="utf-8")

    def add_string_field(self, k: str, v: str) -> "KeepassXCEntry":
        string = ET.SubElement(self.root, "String")
        key = ET.SubElement(string, "Key")
        key.text = k
        value = ET.SubElement(string, "Value")
        value.text = v
        value.set("ProtectInMemory", "True")
        return self

    def add_auto_type(self) -> "KeepassXCEntry":
        autotype = ET.SubElement(self.root, "AutoType")
        enabled = ET.SubElement(autotype, "Enabled")
        enabled.text = "True"
        dto = ET.SubElement(autotype, "DataTransferObfuscation")
        dto.text = "0"
        ET.SubElement(autotype, "DefaultSequence")
        return self


class KeepassXCDump:
    """
    Entire file:

    <?xml version="1.0" encoding="UTF-8" standalone="yes"?>
    <KeePassFile>
      <Root>
        <Group>
                <Name>Root</Name>
                [<Entry>...</Entry>...]
                [<Group>...</Group>...]
        </Group>
      </Root>
    </KeePassFile>
    """

    def __init__(self) -> None:
        self.KeePassFile = ET.Element("KeePassFile")
        Root = ET.SubElement(self.KeePassFile, "Root")
        self.root = ET.SubElement(Root, "Group")
        root_name = ET.SubElement(self.root, "Name")
        root_name.text = "Root"

    def add_group(self, name: str, parent_element: ET.Element) -> ET.Element:
        group_root = ET.SubElement(parent_element, "Group")
        group_name = ET.SubElement(group_root, "Name")
        group_name.text = name

        return group_root

    def __str__(self) -> Any:
        return ET.tostring(self.KeePassFile, encoding="unicode")


def parse_pass_format(
    src: str,
) -> Tuple[str, str, Optional[str], Optional[str], Optional[str]]:
    it = src.split("\n")
    password = it[0]
    totp = next((x for x in it if x.startswith("otpauth://")), None)
    if type(totp) is str:
        it.remove(totp)
    username = next((x for x in it if x.startswith("login:")), None)
    if type(username) is str:
        it.remove(username)
        username = username.removeprefix("login:").strip()
    url = next((x for x in it if x.startswith("url:")), None)
    if type(url) is str:
        it.remove(url)
        url = url.removeprefix("url:").strip()
    notes = "\n".join(it[1:])
    return (password, notes, totp, username, url)


def decrypt(gpg_encrypted_file: Path) -> str:
    out = subprocess.run(
        ["gpg", "--quiet", "--decrypt", gpg_encrypted_file.resolve()],
        capture_output=True,
    )
    return out.stdout.decode("utf-8")


class Converter:
    def to_xml(self, password_store_dir: Path) -> KeepassXCDump:
        self.out = KeepassXCDump()
        self.iterate_over_password_store(password_store_dir, self.out.root)
        return self.out

    def iterate_over_password_store(
        self, current_dir: Path, parent_element: ET.Element
    ) -> None:
        for file_or_dir in (
            x for x in current_dir.iterdir() if x.name[0] != "."
        ):
            if file_or_dir.is_dir():
                group = self.out.add_group(file_or_dir.name, parent_element)
                self.iterate_over_password_store(file_or_dir, group)
            elif file_or_dir.is_file():
                self.add_entry(file_or_dir, parent_element)

    def add_entry(self, file_or_dir: Path, parent_element: ET.Element) -> None:
        print(file_or_dir, file=sys.stderr)
        filename = file_or_dir.name.removesuffix(".gpg")
        try:
            file_contents = decrypt(file_or_dir)
            password, notes, totp, parsed_username, url_parsed = (
                parse_pass_format(file_contents)
            )
            url = url_parsed or filename
            username = parsed_username or filename
            entry = KeepassXCEntry(
                username=username,
                password=password,
                url=url,
                title=username,
                notes=notes,
                totp=totp,
            )
            parent_element.append(entry.root)
        except UnicodeDecodeError:
            print("Skipping due to conversion error!", file=sys.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a pass repository into KeePassXC XML",
    )

    parser.add_argument("password_store_dir")

    args = parser.parse_args()
    password_store_path = Path(args.password_store_dir)
    converter = Converter()
    out = converter.to_xml(password_store_path)
    print(out)


if __name__ == "__main__":
    main()
