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
from typing import List


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

    def __init__(self, username, password, url, title, notes="", totp=""):
        self.root = ET.Element("Entry")
        self.add_string_field("Notes", notes)
        self.add_string_field("UserName", username)
        self.add_string_field("Password", password)
        self.add_string_field("URL", url)
        self.add_string_field("Title", title)
        self.add_string_field("otp", totp)
        self.add_auto_type()

    def __str__(self):
        return ET.tostring(self.root, encoding="utf-8")

    def add_string_field(self, k, v):
        string = ET.SubElement(self.root, "String")
        key = ET.SubElement(string, "Key")
        key.text = k
        value = ET.SubElement(string, "Value")
        value.text = v
        value.set("ProtectInMemory", "True")
        return self

    def add_auto_type(self):
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
                <Name>{group name}</Name>
                [<Entry>...</Entry>...]
        </Group>
      </Root>
    </KeePassFile>
    """

    def __init__(self):
        self.KeePassFile = ET.Element("KeePassFile")
        Root = ET.SubElement(self.KeePassFile, "Root")
        self.root = ET.SubElement(Root, "Group")
        root_name = ET.SubElement(self.root, "Name")
        root_name.text = "Root"

    def add_group(self, name, entries: List[KeepassXCEntry]):
        group_root = ET.SubElement(self.root, "Group")
        group_name = ET.SubElement(group_root, "Name")
        group_name.text = name
        group_root.extend(map(lambda x: x.root, entries))

    def __str__(self):
        return ET.tostring(self.KeePassFile, encoding="unicode")


class KeepassXCGroup:
    def __init__(self, group_name):
        self.root = ET.Element("Group")
        name = ET.SubElement(self.root, "Name")
        name.text = group_name

    def add_entry(self, entry: KeepassXCEntry):
        self.root.append(entry)


def parse_pass_format(src: str):
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


def find_files(directory: Path):
    for node in (x for x in directory.iterdir() if x.name[0] != "."):
        if node.is_dir():
            yield from find_files(Path(node))
        elif node.is_file():
            yield Path(node)


def decrypt(gpg_encrypted_file: Path):
    out = subprocess.run(
        ["gpg", "--quiet", "--decrypt", gpg_encrypted_file.resolve()],
        capture_output=True,
    )
    return out.stdout.decode("utf-8")


def convert_to_xml(password_store_dir: Path) -> KeepassXCDump:
    out = KeepassXCDump()
    for group in (x for x in password_store_dir.iterdir() if x.name[0] != "."):
        # treat a subdirectory as a keeepassxc 'group'
        if group.is_dir():
            keepassxc_entries: List[KeepassXCEntry] = []
            for entry in find_files(group):
                print(entry, file=sys.stderr)
                parent_name = f"{entry.parent.name}"
                default_username = entry.name.removesuffix(".gpg")
                try:
                    file_contents = decrypt(entry)
                except UnicodeDecodeError:
                    # not UTF-8; skip it
                    continue
                password, notes, totp, username, url_parsed = (
                    parse_pass_format(file_contents)
                )
                username = username or default_username
                url = url_parsed or parent_name
                keepassxc_entries.append(
                    KeepassXCEntry(
                        username=username,
                        password=password,
                        url=url,
                        title=username,
                        notes=notes,
                        totp=totp,
                    )
                )
            out.add_group(group.name.removesuffix(".gpg"), keepassxc_entries)
        elif group.is_file():
            keepassxc_entries: List[KeepassXCEntry] = []
            filename = group.name.removesuffix(".gpg")
            try:
                file_contents = decrypt(group)
            except UnicodeDecodeError:
                # not UTF-8; skip it
                continue
            password, notes, totp, username, url_parsed = parse_pass_format(
                file_contents
            )
            url = url_parsed or filename
            keepassxc_entries.append(
                KeepassXCEntry(
                    username=username,
                    password=password,
                    url=url,
                    title=username,
                    notes=notes,
                    totp=totp,
                )
            )
            out.add_group(group.name.removesuffix(".gpg"), keepassxc_entries)

    return out


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert a pass repository into KeePassXC XML",
    )

    parser.add_argument("password_store_dir")

    args = parser.parse_args()
    password_store_path = Path(args.password_store_dir)
    out = convert_to_xml(password_store_path)
    print(out)


if __name__ == "__main__":
    main()
