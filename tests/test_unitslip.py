import io
import json
import os
import stat
import tempfile
import unittest
from contextlib import redirect_stdout

import unitslip
from unitslip import parse_unit_text, rank, scan, main


def write(root, rel, text, mode=0o644):
    p = os.path.join(root, rel)
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)
    os.chmod(p, mode)
    return p


BASE = """[Unit]
Description=web

[Service]
ExecStart=/usr/bin/web
User=web
ProtectSystem=strict
NoNewPrivileges=yes
SystemCallFilter=@system-service
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = self.tmp.name
        self.etc = os.path.join(self.root, "etc")
        self.usr = os.path.join(self.root, "usr")
        os.makedirs(self.etc)
        os.makedirs(self.usr)

    def tearDown(self):
        self.tmp.cleanup()

    def ids(self, *dirs):
        _, f = scan(list(dirs) or [self.etc], fs_root=self.root)
        return [(x.id, x.severity) for x in f], f


class ParserTests(unittest.TestCase):
    def test_sections_comments_continuation(self):
        a = parse_unit_text("# c\n[Service]\n; c\nExecStart=/bin/a \\\n  --flag\nUser = bob\n", "x")
        self.assertEqual([(x.section, x.key, x.value) for x in a],
                         [("Service", "ExecStart", "/bin/a --flag"), ("Service", "User", "bob")])

    def test_malformed_line(self):
        a = parse_unit_text("[Service]\nProtectSystem strict\n", "x")
        self.assertIsNone(a[0].value)

    def test_rank(self):
        self.assertEqual(rank("ProtectSystem", "strict"), 3)
        self.assertEqual(rank("ProtectSystem", "true"), 1)
        self.assertEqual(rank("ProtectHome", "read-only"), 1)
        self.assertEqual(rank("NoNewPrivileges", "on"), 1)
        self.assertIsNone(rank("NoNewPrivileges", "ture"))
        self.assertIsNone(rank("ProtectSystem", "strcit"))
        self.assertEqual(rank("PrivateTmp", ""), 0)


class CleanTests(Base):
    def test_clean_unit_no_findings(self):
        write(self.etc, "web.service", BASE)
        ids, _ = self.ids()
        self.assertEqual(ids, [])

    def test_effective_summary(self):
        write(self.etc, "web.service", BASE)
        reps, _ = scan([self.etc])
        self.assertEqual(reps[0].effective["ProtectSystem"], "strict")
        self.assertIn("SystemCallFilter", reps[0].effective)

    def test_masked_unit_skipped(self):
        write(self.etc, "web.service", "")
        reps, f = scan([self.etc])
        self.assertTrue(reps[0].masked)
        self.assertEqual(f, [])


class SilentIgnoreTests(Base):
    def test_wrong_section(self):
        write(self.etc, "web.service", "[Unit]\nProtectSystem=strict\n[Service]\nExecStart=/usr/bin/web\n")
        ids, _ = self.ids()
        self.assertIn(("US001", "high"), ids)

    def test_typo_and_case(self):
        write(self.etc, "web.service", "[Service]\nExecStart=/usr/bin/web\nProtectSytem=strict\nnonewprivileges=yes\n")
        ids, f = self.ids()
        self.assertEqual(ids.count(("US002", "high")), 2)
        self.assertTrue(any("ProtectSystem=" in x.message for x in f))

    def test_unknown_far_key_is_info(self):
        write(self.etc, "web.service", "[Service]\nExecStart=/usr/bin/web\nFrobnicateEverything=yes\n")
        ids, _ = self.ids()
        self.assertEqual(ids, [("US002", "info")])

    def test_x_keys_ignored(self):
        write(self.etc, "web.service", "[Service]\nExecStart=/usr/bin/web\nX-Owner=team\n[X-Meta]\nA=b\n")
        self.assertEqual(self.ids()[0], [])

    def test_invalid_boolean(self):
        write(self.etc, "web.service", "[Service]\nExecStart=/usr/bin/web\nNoNewPrivileges=ture\nProtectSystem=strcit\n")
        ids, _ = self.ids()
        self.assertEqual(ids.count(("US003", "high")), 2)

    def test_orphan_dropin_key(self):
        write(self.etc, "web.service", BASE)
        write(self.etc, "web.service.d/harden.conf", "ProtectHome=yes\n")
        ids, _ = self.ids()
        self.assertIn(("US012", "high"), ids)

    def test_misspelled_section(self):
        write(self.etc, "web.service", "[Service]\nExecStart=/usr/bin/web\n[Serivce]\nPrivateTmp=yes\n")
        ids, f = self.ids()
        self.assertIn(("US016", "high"), ids)
        self.assertIn("[Service]", f[0].message)

    def test_dropin_without_conf_suffix(self):
        write(self.etc, "web.service", BASE)
        write(self.etc, "web.service.d/override.cnf", "[Service]\nPrivateDevices=yes\n")
        ids, f = self.ids()
        self.assertIn(("US013", "high"), ids)
        self.assertNotIn("PrivateDevices", unitslip.scan([self.etc])[0][0].effective)

    def test_malformed_line_reported(self):
        write(self.etc, "web.service", "[Service]\nExecStart=/usr/bin/web\nPrivateTmp yes\n")
        self.assertIn(("US015", "low"), self.ids()[0])


class OverrideTests(Base):
    def test_dropin_weakens(self):
        write(self.etc, "web.service", BASE)
        write(self.etc, "web.service.d/10-debug.conf", "[Service]\nProtectSystem=full\nNoNewPrivileges=no\n")
        ids, f = self.ids()
        self.assertEqual(ids.count(("US004", "high")), 2)
        reps, _ = scan([self.etc])
        self.assertEqual(reps[0].effective["ProtectSystem"], "full")

    def test_same_file_weaken_is_medium(self):
        write(self.etc, "web.service", BASE + "ProtectSystem=yes\n")
        self.assertIn(("US004", "medium"), self.ids()[0])

    def test_empty_assignment_resets_bool(self):
        write(self.etc, "web.service", BASE)
        write(self.etc, "web.service.d/a.conf", "[Service]\nNoNewPrivileges=\n")
        self.assertIn(("US004", "high"), self.ids()[0])

    def test_list_reset(self):
        write(self.etc, "web.service", BASE)
        write(self.etc, "web.service.d/z.conf", "[Service]\nSystemCallFilter=\n")
        ids, _ = self.ids()
        self.assertIn(("US005", "high"), ids)
        self.assertNotIn("SystemCallFilter", scan([self.etc])[0][0].effective)

    def test_dropin_order_by_filename(self):
        write(self.etc, "web.service", BASE)
        write(self.etc, "web.service.d/90-tight.conf", "[Service]\nProtectHome=yes\n")
        write(self.etc, "web.service.d/10-loose.conf", "[Service]\nProtectHome=no\n")
        ids, _ = self.ids()
        self.assertEqual(ids, [])
        self.assertEqual(scan([self.etc])[0][0].effective["ProtectHome"], "yes")

    def test_higher_priority_dropin_masks_same_name(self):
        write(self.usr, "web.service", BASE)
        write(self.usr, "web.service.d/harden.conf", "[Service]\nPrivateTmp=yes\n")
        write(self.etc, "web.service.d/harden.conf", "[Service]\nUMask=0077\n")
        reps, _ = scan([self.etc, self.usr])
        self.assertNotIn("PrivateTmp", reps[0].effective)

    def test_toplevel_and_prefix_dropins_apply(self):
        write(self.etc, "app-web.service", BASE)
        write(self.etc, "app-.service.d/a.conf", "[Service]\nProtectSystem=no\n")
        write(self.etc, "service.d/b.conf", "[Service]\nPrivateTmp=yes\n")
        reps, f = scan([self.etc])
        self.assertIn("PrivateTmp", reps[0].effective)
        self.assertIn("US004", [x.id for x in f])

    def test_full_copy_drops_vendor_hardening(self):
        write(self.usr, "web.service", BASE + "PrivateDevices=yes\n")
        write(self.etc, "web.service", "[Service]\nExecStart=/usr/bin/web\nUser=web\nProtectSystem=full\n")
        ids, f = self.ids(self.etc, self.usr)
        self.assertIn(("US014", "high"), ids)
        msg = [x for x in f if x.id == "US014"][0].message
        self.assertIn("ProtectSystem=strict", msg)
        self.assertIn("PrivateDevices=yes", msg)


class PrivilegeTests(Base):
    def test_plus_prefix_bypasses_sandbox(self):
        write(self.etc, "web.service", BASE + "ExecStartPre=+/usr/bin/setup\n")
        self.assertIn(("US006", "high"), self.ids()[0])

    def test_plus_prefix_unsandboxed_unit_quiet(self):
        write(self.etc, "web.service", "[Service]\nExecStart=+/usr/bin/web\n")
        self.assertNotIn("US006", [i for i, _ in self.ids()[0]])

    def test_bang_prefix_drops_user(self):
        write(self.etc, "web.service", "[Service]\nUser=web\nExecStart=!/usr/bin/web\n")
        self.assertIn(("US006", "medium"), self.ids()[0])

    def test_root_exec_from_tmp(self):
        write(self.etc, "web.service", "[Service]\nExecStart=/tmp/agent --serve\n")
        self.assertIn(("US009", "high"), self.ids()[0])

    def test_nonroot_exec_from_home_ok(self):
        write(self.etc, "web.service", "[Service]\nUser=bob\nExecStart=/home/bob/app\n")
        self.assertEqual(self.ids()[0], [])

    def test_world_writable_binary(self):
        write(self.root, "opt/tool/run", "#!/bin/sh\n", mode=0o777)
        write(self.etc, "web.service", "[Service]\nExecStart=/opt/tool/run\n")
        self.assertIn(("US009", "high"), self.ids()[0])

    def test_rw_hole_escalation(self):
        write(self.etc, "web.service", BASE + "ReadWritePaths=-/etc/systemd /var/lib/web\n")
        ids, f = self.ids()
        self.assertEqual(ids.count(("US007", "medium")), 1)

    def test_rw_subdir_of_lib_is_fine(self):
        write(self.etc, "web.service", BASE + "ReadWritePaths=/usr/lib/locale\n")
        self.assertEqual(self.ids()[0], [])

    def test_alias_symlink_skipped(self):
        write(self.etc, "web.service", BASE + "ReadWritePaths=/\n")
        os.symlink(os.path.join(self.etc, "web.service"), os.path.join(self.etc, "alias-web.service"))
        reps, f = scan([self.etc])
        self.assertEqual([r.name for r in reps], ["web.service"])

    def test_rw_root_cancels_strict(self):
        write(self.etc, "web.service", BASE + "ReadWritePaths=/\n")
        self.assertIn(("US007", "high"), self.ids()[0])

    def test_rw_not_covered_is_quiet(self):
        write(self.etc, "web.service", "[Service]\nExecStart=/usr/bin/web\nUser=web\nProtectSystem=yes\nReadWritePaths=/etc/sudoers.d\n")
        self.assertEqual(self.ids()[0], [])

    def test_rw_home_ssh(self):
        write(self.etc, "web.service", BASE + "ProtectHome=read-only\nReadWritePaths=/home/alice\n")
        self.assertIn(("US007", "medium"), self.ids()[0])

    def test_env_secret_masked(self):
        write(self.etc, "web.service", BASE + 'Environment="DB_PASSWORD=hunter22" MODE=prod\n')
        ids, f = self.ids()
        self.assertIn(("US008", "medium"), ids)
        self.assertNotIn("hunter22", json.dumps([x.to_dict() for x in f]))

    def test_env_reference_ok(self):
        write(self.etc, "web.service", BASE + "Environment=API_TOKEN=%d/token\n")
        self.assertEqual(self.ids()[0], [])

    def test_ambient_caps(self):
        write(self.etc, "web.service", BASE + "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_ADMIN\n")
        ids, f = self.ids()
        self.assertEqual(ids.count(("US011", "high")), 1)

    def test_ambient_inverted(self):
        write(self.etc, "web.service", BASE + "AmbientCapabilities=~CAP_SYS_BOOT\n")
        self.assertIn(("US011", "high"), self.ids()[0])

    def test_world_writable_unit_file(self):
        write(self.etc, "web.service", BASE, mode=0o666)
        self.assertIn(("US010", "high"), self.ids()[0])


class CliTests(Base):
    def run_cli(self, *argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(list(argv))
        return code, buf.getvalue()

    def test_exit_codes(self):
        write(self.etc, "web.service", BASE)
        self.assertEqual(self.run_cli(self.etc)[0], 0)
        write(self.etc, "web.service.d/x.conf", "[Service]\nProtectSystem=no\n")
        code, out = self.run_cli(self.etc)
        self.assertEqual(code, 1)
        self.assertIn("US004", out)
        self.assertEqual(self.run_cli(self.etc, "--fail-on", "never")[0], 0)

    def test_json_and_single_file(self):
        p = write(self.etc, "web.service", "[Unit]\nNoNewPrivileges=yes\n[Service]\nExecStart=/usr/bin/web\n")
        write(self.etc, "other.service", "[Unit]\nPrivateTmp=yes\n")
        code, out = self.run_cli(p, "--json")
        data = json.loads(out)
        self.assertEqual([u["name"] for u in data["units"]], ["web.service"])
        self.assertEqual(data["findings"][0]["id"], "US001")


if __name__ == "__main__":
    unittest.main()
