import asyncio
import sys
import unittest

from bloodyAD import asciitree, utils
from bloodyAD.main import amain


class LazyAdSchemaTests(unittest.IsolatedAsyncioTestCase):
    async def test_resolves_identifiers_added_after_previous_batch(self):
        schema = utils.LazyAdSchema()
        schema.guids = set()
        schema.sids = set()
        schema.DNs = set()
        schema.guid_dict = {}
        schema.sid_dict = {}
        schema.dn_dict = {}
        schema.isResolved = False

        async def resolve_pending():
            for guid in schema.guids:
                schema.guid_dict[guid] = f"resolved-{guid}"
            schema.isResolved = True
            schema.guids = set()

        schema._resolveAll = resolve_pending

        schema.addguid("first-guid")
        self.assertEqual(await schema.getguid("first-guid"), "resolved-first-guid")
        self.assertTrue(schema.isResolved)

        schema.addguid("second-guid")
        self.assertFalse(schema.isResolved)
        self.assertEqual(await schema.getguid("second-guid"), "resolved-second-guid")

    def test_new_unknown_identifier_reopens_resolution(self):
        schema = utils.LazyAdSchema()
        schema.guids = set()
        schema.sids = set()
        schema.DNs = set()
        schema.guid_dict = {}
        schema.sid_dict = {}
        schema.dn_dict = {}

        schema.isResolved = True
        schema.addguid("unknown-guid")
        self.assertFalse(schema.isResolved)

        schema.isResolved = True
        schema.addsid("S-1-5-21-1")
        self.assertFalse(schema.isResolved)

        schema.isResolved = True
        schema.adddn("CN=Unknown,DC=example,DC=com")
        self.assertFalse(schema.isResolved)


class UnitTests(unittest.TestCase):
    def test_01TreeDisplay(self):
        trust_dict = trust_dict = {
            "child.bloody.lab": {
                "bloody.lab": {
                    "distinguishedName": (
                        "CN=bloody.lab,CN=System,DC=child,DC=bloody,DC=lab"
                    ),
                    "trustDirection": [b"3"],
                    "trustPartner": [b"bloody.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                }
            },
            "cousin.corp": {
                "bloody.lab": {
                    "distinguishedName": "CN=bloody.lab,CN=System,DC=cousin,DC=corp",
                    "trustDirection": [b"3"],
                    "trustPartner": [b"bloody.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                }
            },
            "stranger.lab": {
                "bloody.lab": {
                    "distinguishedName": "CN=bloody.lab,CN=System,DC=stranger,DC=lab",
                    "trustDirection": [b"3"],
                    "trustPartner": [b"bloody.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"8"],
                },
                "cousin.corp": {
                    "distinguishedName": "CN=cousin.corp,CN=System,DC=bloody,DC=lab",
                    "trustDirection": [b"1"],
                    "trustPartner": [b"cousin.corp"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                },
                "business.corp": {
                    "distinguishedName": "CN=business.corp,CN=System,DC=bloody,DC=lab",
                    "trustDirection": [b"1"],
                    "trustPartner": [b"business.corp"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                },
            },
            "bloody.lab": {
                "child.bloody.lab": {
                    "distinguishedName": (
                        "CN=child.bloody.lab,CN=System,DC=bloody,DC=lab"
                    ),
                    "trustDirection": [b"3"],
                    "trustPartner": [b"child.bloody.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"32"],
                },
                "cousin.corp": {
                    "distinguishedName": "CN=cousin.corp,CN=System,DC=bloody,DC=lab",
                    "trustDirection": [b"3"],
                    "trustPartner": [b"cousin.corp"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"0"],
                },
                "stranger.lab": {
                    "distinguishedName": "CN=stranger.lab,CN=System,DC=bloody,DC=lab",
                    "trustDirection": [b"3"],
                    "trustPartner": [b"stranger.lab"],
                    "trustType": [b"2"],
                    "trustAttributes": [b"8"],
                },
            },
        }
        trust_root_domain = "bloody.lab"
        tree = {}
        asciitree.branchFactory({":" + trust_root_domain: tree}, [], trust_dict)
        tree_printer = asciitree.LeftAligned()
        print(tree_printer({trust_root_domain: tree}))

    def test_02CaseInsensitiveCommands(self):
        """Test that subcommands are case-insensitive"""
        test_cases = [
            # Test lowercase
            ["--host", "test.local", "add", "genericall", "--help"],
            # Test uppercase
            ["--host", "test.local", "add", "GENERICALL", "--help"],
            # Test mixed case
            ["--host", "test.local", "add", "GenericAll", "--help"],
            # Test shadowCredentials variations
            ["--host", "test.local", "add", "shadowcredentials", "--help"],
            ["--host", "test.local", "add", "SHADOWCREDENTIALS", "--help"],
            ["--host", "test.local", "add", "ShadowCredentials", "--help"],
            # Test gmsaGroup variations
            ["--host", "test.local", "add", "gmsagroup", "--help"],
            ["--host", "test.local", "add", "GMSAGROUP", "--help"],
            ["--host", "test.local", "add", "gmsaGroup", "--help"],
            # Test get module
            ["--host", "test.local", "get", "object", "--help"],
            ["--host", "test.local", "get", "OBJECT", "--help"],
            # Test remove module  
            ["--host", "test.local", "remove", "genericall", "--help"],
            ["--host", "test.local", "remove", "SHADOWCREDENTIALS", "--help"],
        ]
        
        for test_args in test_cases:
            with self.subTest(args=test_args):
                sys.argv = ["bloodyAD.py"] + test_args
                try:
                    # The --help flag will cause SystemExit(0) which is expected
                    asyncio.run(amain())
                    self.fail("Expected SystemExit from --help")
                except SystemExit as e:
                    # --help should exit with code 0
                    self.assertEqual(e.code, 0, f"Command failed with args: {test_args}")
