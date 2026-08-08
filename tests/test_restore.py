import importlib
import unittest
from unittest.mock import AsyncMock, MagicMock

from bloodyAD.network.ldap import Change, Scope, showRecoverable


set_module = importlib.import_module("bloodyAD.cli_modules.set")

SHOW_DELETED = [("1.2.840.113556.1.4.417", True, None)]
DELETED_DN = (
    r"CN=BackupUsers\0ADEL:2656badc-09ec-4036-ad8c-9c9de5857df8,"
    r"CN=Deleted Objects,DC=tombwatcher,DC=htb"
)
NEW_PARENT = "OU=Custom,DC=tombwatcher,DC=htb"


class FakeConnection:
    def __init__(self, ldap):
        self.ldap = ldap

    async def getLdap(self):
        return self.ldap


class RestoreTests(unittest.IsolatedAsyncioTestCase):
    def make_ldap(self):
        ldap = MagicMock()
        ldap.domainNC = "DC=tombwatcher,DC=htb"
        ldap.bloodymodify = AsyncMock()
        return ldap

    async def test_exact_tombstone_dn_restores_directly_without_new_name(self):
        ldap = self.make_ldap()
        conn = FakeConnection(ldap)

        await set_module.restore(conn, DELETED_DN, newParent=NEW_PARENT)

        ldap.bloodysearch.assert_not_called()
        ldap.bloodymodify.assert_awaited_once_with(
            DELETED_DN,
            {
                "distinguishedName": [
                    (Change.REPLACE.value, f"CN=BackupUsers,{NEW_PARENT}")
                ],
                "isDeleted": [(Change.DELETE.value, [])],
            },
            controls=SHOW_DELETED,
            is_restore=True,
        )

    async def test_exact_tombstone_dn_restores_directly_with_new_name(self):
        ldap = self.make_ldap()
        conn = FakeConnection(ldap)

        await set_module.restore(
            conn, DELETED_DN, newName="RestoredUsers", newParent=NEW_PARENT
        )

        ldap.bloodysearch.assert_not_called()
        ldap.bloodymodify.assert_awaited_once_with(
            DELETED_DN,
            {
                "distinguishedName": [
                    (Change.REPLACE.value, f"CN=RestoredUsers,{NEW_PARENT}")
                ],
                "isDeleted": [(Change.DELETE.value, [])],
            },
            controls=SHOW_DELETED,
            is_restore=True,
        )

    async def test_ordinary_identifier_keeps_metadata_lookup_and_rename_updates(self):
        ldap = self.make_ldap()
        entry = {
            "distinguishedName": DELETED_DN,
            "lastKnownParent": "CN=Users,DC=tombwatcher,DC=htb",
            "msDS-LastKnownRDN": "BackupUsers",
            "name": "BackupUsers\nDEL:2656badc-09ec-4036-ad8c-9c9de5857df8",
            "displayName": "BackupUsers",
            "sAMAccountName": "BackupUsers",
            "servicePrincipalName": ["service/BackupUsers"],
            "userPrincipalName": "BackupUsers@tombwatcher.htb",
            "dNSHostName": "BackupUsers.tombwatcher.htb",
        }

        async def search_results():
            yield entry

        ldap.bloodysearch.return_value = search_results()
        conn = FakeConnection(ldap)

        await set_module.restore(
            conn, "BackupUsers", newName="RestoredUsers", newParent=NEW_PARENT
        )

        ldap.bloodysearch.assert_called_once_with(
            "CN=Deleted Objects,DC=tombwatcher,DC=htb",
            "(&(sAMAccountName=BackupUsers)(isDeleted=TRUE))",
            search_scope=Scope.SUBTREE,
            attr=[
                "msDS-LastKnownRDN",
                "lastKnownParent",
                "sAMAccountName",
                "servicePrincipalName",
                "userPrincipalName",
                "name",
                "dNSHostName",
                "displayName",
            ],
            controls=showRecoverable(),
        )
        changes = ldap.bloodymodify.await_args.args[1]
        self.assertEqual(
            changes["distinguishedName"],
            [(Change.REPLACE.value, f"CN=RestoredUsers,{NEW_PARENT}")],
        )
        self.assertIn("sAMAccountName", changes)
        self.assertIn("servicePrincipalName", changes)
        self.assertIn("userPrincipalName", changes)
        self.assertIn("dNSHostName", changes)
        self.assertIn("displayName", changes)

    async def test_exact_tombstone_dn_without_parent_keeps_metadata_lookup(self):
        ldap = self.make_ldap()
        entry = {
            "distinguishedName": DELETED_DN,
            "lastKnownParent": NEW_PARENT,
            "msDS-LastKnownRDN": "BackupUsers",
            "name": "BackupUsers\nDEL:2656badc-09ec-4036-ad8c-9c9de5857df8",
        }

        async def search_results():
            yield entry

        ldap.bloodysearch.return_value = search_results()

        await set_module.restore(FakeConnection(ldap), DELETED_DN)

        ldap.bloodysearch.assert_called_once()
        ldap.bloodymodify.assert_awaited_once()

    async def test_malformed_tombstone_dn_is_not_treated_as_direct(self):
        ldap = self.make_ldap()
        malformed_dn = (
            r"CN=BackupUsers\0ADEL:not-a-guid,CN=Deleted Objects,"
            r"DC=tombwatcher,DC=htb"
        )
        entry = {
            "distinguishedName": malformed_dn,
            "lastKnownParent": NEW_PARENT,
            "msDS-LastKnownRDN": "BackupUsers",
            "name": "BackupUsers\nDEL:not-a-guid",
        }

        async def search_results():
            yield entry

        ldap.bloodysearch.return_value = search_results()

        await set_module.restore(
            FakeConnection(ldap), malformed_dn, newParent=NEW_PARENT
        )

        ldap.bloodysearch.assert_called_once()
        ldap.bloodymodify.assert_awaited_once_with(
            malformed_dn,
            {
                "distinguishedName": [
                    (Change.REPLACE.value, f"CN=BackupUsers,{NEW_PARENT}")
                ],
                "isDeleted": [(Change.DELETE.value, [])],
            },
            controls=SHOW_DELETED,
            is_restore=True,
        )


if __name__ == "__main__":
    unittest.main()
