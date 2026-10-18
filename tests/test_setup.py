import io
import json
import unittest
from unittest.mock import patch

from dh_tux_initialize.discovery import DiscoveredDevice
from dh_tux_initialize.setup import SetupPlan, _finish_preflight, run_setup


def make_device(
    mac,
    init=3733,
    *,
    model="IPC-Test",
    ip="192.0.2.108",
    serial=None,
    firmware="TEST-FIRMWARE-BASE",
    mask=None,
    gateway=None,
):
    address = {"IPAddress": ip}
    if mask is not None:
        address["SubnetMask"] = mask
    if gateway is not None:
        address["DefaultGateway"] = gateway
    info = {
        "Mac": mac,
        "IPv4Address": address,
        "DeviceType": model,
        "SerialNo": serial or f"TESTSERIAL-{mac[-2:]}",
        "Version": firmware,
        "Init": init,
    }
    return DiscoveredDevice(info, {}, ip, valid_dhip_identity=True, dahua_verified=True)


class InputSequence:
    def __init__(self, values):
        self.values = iter(values)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        return next(self.values)


class PasswordSequence:
    def __init__(self, values):
        self.values = iter(values)
        self.prompts = []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        return next(self.values)


class SetupWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.output = io.StringIO()

    def run_flow(
        self,
        devices,
        inputs,
        passwords=(),
        *,
        show_all=False,
        rescans=(),
        terminal_size=(100, 30),
    ):
        self.inputs = InputSequence(inputs)
        self.passwords = PasswordSequence(passwords)
        remaining_rescans = list(rescans)
        latest_scan = [list(devices)]

        def scan_fn():
            if remaining_rescans:
                latest_scan[0] = list(remaining_rescans.pop(0))
            return latest_scan[0]

        self.provision_calls = []

        def provision_fn(plan, device):
            self.provision_calls.append((plan.mac, device.mac))
            if isinstance(device.info, dict):
                device.info["Init"] = 3734

        return run_setup(
            devices,
            show_all=show_all,
            input_fn=self.inputs,
            password_fn=self.passwords,
            rescan_fn=scan_fn,
            output=self.output,
            terminal_size_fn=lambda: terminal_size,
            interactive=False,
            provision_fn=provision_fn,
        )

    def run_flow_with_fake_clock(self, *args, **kwargs):
        clock = [0.0]

        def advance(seconds):
            clock[0] += seconds

        with patch(
            "dh_tux_initialize.setup.time.monotonic",
            side_effect=lambda: clock[0],
        ), patch("dh_tux_initialize.setup.time.sleep", side_effect=advance):
            return self.run_flow(*args, **kwargs)

    def test_main_screen_uses_compact_english_columns(self):
        device = make_device(
            "02:00:00:00:00:01",
            model="IPC-Test-Camera",
            ip="192.0.2.108",
            serial="TESTSERIAL001",
            firmware="TEST-FIRMWARE-001",
        )

        self.run_flow([device], ["f"])

        output = self.output.getvalue()
        self.assertIn("DH-Tux-Initialize\n\nDahua devices", output)
        self.assertIn("Found 1 device: 1 uninitialized, 0 initialized, 0 unknown.", output)
        self.assertIn("No.  Model            MAC                Current IP   Status", output)
        self.assertIn("1    IPC-Test-Camera  02:00:00:00:00:01  192.0.2.108  Uninitialized", output)
        self.assertNotIn("TESTSERIAL001", output)
        self.assertNotIn("TEST-FIRMWARE-001", output)
        self.assertIn("[1] Select device   [r] Rescan   [p] Plans   [f] Finish   [q] Cancel", output)
        self.assertNotIn("\x1b[", output)

    def test_tty_screens_clear_with_ansi_sequences(self):
        device = make_device("02:00:00:00:00:02")
        output = io.StringIO()

        run_setup(
            [device],
            input_fn=InputSequence(["f"]),
            output=output,
            terminal_size_fn=lambda: (100, 30),
            interactive=True,
        )

        self.assertIn("\x1b[2J\x1b[H", output.getvalue())

    def test_device_details_precede_network_configuration_and_password(self):
        device = make_device(
            "02:00:00:00:00:02",
            model="IPC-Test-Camera",
            serial="TESTSERIAL001",
            firmware="TEST-FIRMWARE-001",
        )

        plans = self.run_flow([device], ["1", "b", "f"])

        output = self.output.getvalue()
        self.assertEqual(plans, [])
        self.assertIn("Device\n───────────────────────────────────────", output)
        self.assertIn("Model:       IPC-Test-Camera", output)
        self.assertIn("MAC:         02:00:00:00:00:02", output)
        self.assertIn("Serial:      TESTSERIAL001", output)
        self.assertIn("Firmware:    TEST-FIRMWARE-001", output)
        self.assertLess(output.index("Network configuration"), output.index("Planned setup"))
        self.assertEqual(self.passwords.prompts, [])

    def test_dhcp_plan_is_saved_and_finish_shows_password_configured_only(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")
        rediscovered = make_device(
            device.mac,
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.172",
        )

        plans = self.run_flow(
            [device], ["1", "d", "f", "y"], ["x", "x"], rescans=[[rediscovered]]
        )

        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].network_mode, "dhcp")
        output = self.output.getvalue()
        self.assertIn("Setup plan saved.\n\nIPC-Test-Camera\nNetwork: DHCP", output)
        self.assertIn("Admin password: configured", output)
        self.assertIn("Apply setup to 1 device? [y/N]", self.inputs.prompts)
        self.assertIn("Setup completed.", output)
        self.assertIn("IPC-Test-Camera  02:00:00:00:00:02  10.42.0.172  Initialized", output)
        self.assertNotIn("DRY RUN", output)
        self.assertEqual(self.provision_calls, [(device.mac, device.mac)])
        self.assertNotIn("\n   Admin password: x", output)
        self.assertEqual(self.passwords.prompts, ["Admin password: ", "Confirm admin password: "])

    def test_finish_displays_the_rediscovered_dhcp_address(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")
        rediscovered = make_device(
            "02:00:00:00:00:02",
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.108",
        )

        self.run_flow([device], ["1", "d", "f", "y"], ["x", "x"], rescans=[[rediscovered]])

        self.assertIn(
            "IPC-Test-Camera  02:00:00:00:00:02  10.42.0.108  Initialized",
            self.output.getvalue(),
        )

    def test_dhcp_rediscovery_waits_through_old_address_until_new_address(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")
        new_address = make_device(
            "02:00:00:00:00:02",
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.172",
        )

        self.run_flow_with_fake_clock(
            [device],
            ["1", "d", "f", "y"],
            ["x", "x"],
            rescans=[[device], [device], [new_address]],
        )

        output = self.output.getvalue()
        self.assertIn(
            "IPC-Test-Camera  02:00:00:00:00:02  10.42.0.172  Initialized",
            output,
        )
        self.assertNotIn("Setup failed for", output)

    def test_dhcp_rediscovery_timeout_keeps_success_when_only_old_address_appears(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")

        self.run_flow_with_fake_clock(
            [device],
            ["1", "d", "f", "y"],
            ["x", "x"],
            rescans=[[device]],
        )

        output = self.output.getvalue()
        self.assertIn("Setup completed.", output)
        self.assertIn("Device initialized and DHCP enabled.", output)
        self.assertIn("New IP not discovered yet.", output)
        self.assertNotIn("Setup failed for", output)
        self.assertNotIn(
            "IPC-Test-Camera  02:00:00:00:00:02  192.0.2.108  Initialized",
            output,
        )

    def test_dhcp_rediscovery_waits_when_camera_disappears_briefly(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")
        new_address = make_device(
            "02:00:00:00:00:02",
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.172",
        )

        self.run_flow_with_fake_clock(
            [device],
            ["1", "d", "f", "y"],
            ["x", "x"],
            rescans=[[], [new_address]],
        )

        self.assertIn(
            "IPC-Test-Camera  02:00:00:00:00:02  10.42.0.172  Initialized",
            self.output.getvalue(),
        )

    def test_dhcp_rediscovery_ignores_other_mac_at_new_address(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")
        other_mac = make_device(
            "02:00:00:00:00:03",
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.200",
        )
        new_address = make_device(
            "02:00:00:00:00:02",
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.172",
        )

        self.run_flow_with_fake_clock(
            [device],
            ["1", "d", "f", "y"],
            ["x", "x"],
            rescans=[[device], [other_mac], [new_address]],
        )

        output = self.output.getvalue()
        self.assertIn(
            "IPC-Test-Camera  02:00:00:00:00:02  10.42.0.172  Initialized",
            output,
        )
        self.assertNotIn("10.42.0.200  Initialized", output)

    def test_static_rediscovery_waits_for_planned_address_after_old_address(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")
        target_address = make_device(
            device.mac,
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.68",
        )

        self.run_flow_with_fake_clock(
            [device],
            ["1", "s", "10.42.0.68", "255.255.255.0", "10.42.0.1", "f", "y"],
            ["x", "x"],
            rescans=[[device], [target_address]],
        )

        output = self.output.getvalue()
        self.assertIn(
            "IPC-Test-Camera  02:00:00:00:00:02  10.42.0.68  Initialized",
            output,
        )
        self.assertNotIn("Setup failed for", output)

    def test_static_rediscovery_does_not_accept_unexpected_ip_for_same_mac(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")
        unexpected_address = make_device(
            device.mac,
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.90",
        )

        self.run_flow_with_fake_clock(
            [device],
            ["1", "s", "10.42.0.68", "255.255.255.0", "10.42.0.1", "f", "y"],
            ["x", "x"],
            rescans=[[unexpected_address]],
        )

        output = self.output.getvalue()
        self.assertNotIn("Setup completed.", output)
        self.assertIn("Static configuration applied.", output)
        self.assertIn("Configured IP not rediscovered yet.", output)
        self.assertNotIn("10.42.0.90  Initialized", output)

    def test_static_rediscovery_does_not_accept_other_mac_at_target_ip(self):
        device = make_device("02:00:00:00:00:02", model="IPC-Test-Camera")
        other_mac = make_device(
            "02:00:00:00:00:03",
            init=3734,
            model="IPC-Test-Camera",
            ip="10.42.0.68",
        )

        self.run_flow_with_fake_clock(
            [device],
            ["1", "s", "10.42.0.68", "255.255.255.0", "10.42.0.1", "f", "y"],
            ["x", "x"],
            rescans=[[other_mac]],
        )

        output = self.output.getvalue()
        self.assertNotIn("Setup completed.", output)
        self.assertIn("Configured IP not rediscovered yet.", output)
        self.assertNotIn("02:00:00:00:00:03  10.42.0.68  Initialized", output)

    def test_static_network_defaults_are_accepted_by_enter(self):
        device = make_device(
            "02:00:00:00:00:02",
            mask="255.255.255.0",
            gateway="192.0.2.1",
        )
        rediscovered = make_device(
            device.mac,
            init=3734,
            model="IPC-Test",
            ip="192.0.2.50",
        )

        plans = self.run_flow(
            [device],
            ["1", "s", "192.0.2.50", "", "", "f", "y"],
            ["x", "x"],
            rescans=[[rediscovered]],
        )

        self.assertEqual(plans[0].ipv4, "192.0.2.50")
        self.assertEqual(plans[0].netmask, "255.255.255.0")
        self.assertEqual(plans[0].gateway, "192.0.2.1")
        self.assertIn("Subnet mask [255.255.255.0]: ", self.inputs.prompts)
        self.assertIn("Gateway [192.0.2.1]: ", self.inputs.prompts)
        self.assertIn("Setup completed.", self.output.getvalue())
        self.assertIn(
            "IPC-Test  02:00:00:00:00:02  192.0.2.50  Initialized",
            self.output.getvalue(),
        )

    def test_incomplete_static_plan_is_rejected_by_finish_preflight(self):
        device = make_device("02:00:00:00:00:02")
        plan = SetupPlan(
            mac=device.mac,
            model="IPC-Test",
            password="synthetic-secret",
            network_mode="static",
            ipv4="10.42.0.68",
            netmask=None,
            gateway="10.42.0.1",
        )

        errors = _finish_preflight(
            [plan], {device.mac.casefold(): device}, lambda: [device]
        )

        self.assertEqual(len(errors), 1)
        self.assertIn("static network plan is incomplete", errors[0][1])

    def test_static_network_validation_still_rejects_invalid_values(self):
        device = make_device("02:00:00:00:00:02")

        plans = self.run_flow(
            [device],
            [
                "1", "s", "999.1.1.1", "192.0.2.50",
                "255.0.255.0", "255.255.255.0",
                "not-an-ip", "192.0.2.1", "f", "n",
            ],
            ["x", "x"],
        )

        self.assertEqual(plans[0].ipv4, "192.0.2.50")
        output = self.output.getvalue()
        self.assertIn("Invalid IP address", output)
        self.assertIn("Invalid Subnet mask", output)
        self.assertIn("Invalid Gateway", output)

    def test_password_mismatch_retries_without_leaking_or_repr_output(self):
        device = make_device("02:00:00:00:00:02")
        rediscovered = make_device(
            device.mac, init=3734, ip="10.42.0.172"
        )

        plans = self.run_flow(
            [device],
            ["1", "d", "f", "y"],
            ["first-dummy", "second-dummy", "saved-dummy", "saved-dummy"],
            rescans=[[rediscovered]],
        )

        self.assertEqual(len(plans), 1)
        output = self.output.getvalue()
        self.assertIn("Passwords do not match. Please try again.", output)
        for dummy in ("first-dummy", "second-dummy", "saved-dummy"):
            self.assertNotIn(dummy, output)
            self.assertNotIn(dummy, repr(plans[0]))
            self.assertNotIn(dummy, json.dumps(plans[0].to_json_dict()))

    def test_rescan_updates_devices_and_preserves_plan_by_mac(self):
        original = make_device("02:00:00:00:00:02", model="IPC-Old")
        rediscovered = make_device(
            "02:00:00:00:00:02",
            model="IPC-New",
            ip="192.0.2.150",
        )
        new_address = make_device(
            "02:00:00:00:00:02",
            init=3734,
            model="IPC-New",
            ip="10.42.0.172",
        )

        plans = self.run_flow(
            [original],
            ["1", "d", "r", "f", "y"],
            ["x", "x"],
            rescans=[[rediscovered], [new_address]],
        )

        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].mac, original.mac)
        output = self.output.getvalue()
        self.assertIn("Scanning for Dahua devices...", output)
        self.assertIn("Found 1 device: 1 uninitialized, 0 initialized, 0 unknown.", output)
        self.assertIn("IPC-New", output)
        self.assertIn("DHCP", output)
        table_headers = [line for line in output.splitlines() if line.startswith("No.")]
        self.assertTrue(any("Plan" in line for line in table_headers))

    def test_empty_device_list_stays_open_and_rescans(self):
        device = make_device("02:00:00:00:00:02")

        self.run_flow([], ["r", "f"], rescans=[[device]])

        output = self.output.getvalue()
        self.assertIn("No uninitialized devices found.", output)
        self.assertIn("Found 1 device: 1 uninitialized, 0 initialized, 0 unknown.", output)
        self.assertIn("02:00:00:00:00:02", output)
        self.assertIn("[r] Rescan   [p] Plans   [f] Finish   [q] Cancel", output)

    def test_rescan_to_empty_list_keeps_plans_available(self):
        device = make_device("02:00:00:00:00:02")
        new_address = make_device(
            device.mac, init=3734, ip="10.42.0.172"
        )

        plans = self.run_flow(
            [device],
            ["1", "d", "r", "p", "b", "f", "y"],
            ["x", "x"],
            rescans=[[], [new_address]],
        )

        self.assertEqual(len(plans), 1)
        self.assertIn("No uninitialized devices found.", self.output.getvalue())
        self.assertIn("1  IPC-Test  02:00:00:00:00:02  DHCP", self.output.getvalue())

    def test_deep_scan_is_not_offered_or_dispatched_by_setup_screen(self):
        self.run_flow([], ["d", "q"])

        output = self.output.getvalue()
        self.assertNotIn("[d] Deep scan", output)
        self.assertNotIn("Deep scanning", output)
        self.assertIn("Choose a device number, r, p, f, or q.", output)

    def test_existing_plan_can_be_edited(self):
        device = make_device("02:00:00:00:00:02", mask="255.255.255.0", gateway="192.0.2.1")

        plans = self.run_flow(
            [device],
            ["1", "d", "1", "e", "s", "192.0.2.51", "", "", "f", "n"],
            ["x", "x", "y", "y"],
        )

        self.assertEqual(len(plans), 1)
        self.assertEqual(plans[0].network_mode, "static")
        self.assertEqual(plans[0].ipv4, "192.0.2.51")
        output = self.output.getvalue()
        self.assertIn("A setup plan already exists for this device.", output)
        self.assertIn("Setup plan updated.", output)

    def test_existing_plan_can_be_deleted(self):
        device = make_device("02:00:00:00:00:02")

        plans = self.run_flow([device], ["1", "d", "1", "d", "f"], ["x", "x"])

        self.assertEqual(plans, [])
        self.assertIn("Setup plan deleted.", self.output.getvalue())
        self.assertIn("No setup plans.", self.output.getvalue())

    def test_plans_screen_can_manage_and_delete_a_plan(self):
        device = make_device("02:00:00:00:00:02")

        plans = self.run_flow(
            [device], ["1", "d", "p", "1", "d", "b", "f"], ["x", "x"]
        )

        self.assertEqual(plans, [])
        self.assertIn("[number] Manage plan   [b] Back", self.output.getvalue())
        self.assertIn("Setup plan deleted.", self.output.getvalue())

    def test_finish_and_cancel_are_separate(self):
        device = make_device("02:00:00:00:00:02")
        rediscovered = make_device(
            device.mac, init=3734, ip="10.42.0.172"
        )
        finished = self.run_flow(
            [device], ["1", "d", "f", "y"], ["x", "x"], rescans=[[rediscovered]]
        )
        self.assertEqual(len(finished), 1)
        self.assertIn("Planned setup", self.output.getvalue())

        self.output = io.StringIO()
        device = make_device("02:00:00:00:00:02")
        cancelled = self.run_flow([device], ["1", "d", "q", "y"], ["x", "x"])
        self.assertEqual(cancelled, [])
        self.assertIn("Discard 1 setup plan and quit? [y/N]: ", self.inputs.prompts)
        self.assertIn("Plans discarded.", self.output.getvalue())
        self.assertNotIn("Admin password: configured", self.output.getvalue())

    def test_cancel_can_be_declined_and_finish_keeps_the_plan(self):
        device = make_device("02:00:00:00:00:02")

        plans = self.run_flow([device], ["1", "d", "q", "n", "f", "n"], ["x", "x"])

        self.assertEqual(len(plans), 1)
        self.assertIn("Discard 1 setup plan and quit? [y/N]: ", self.inputs.prompts)
        self.assertIn("Admin password: configured", self.output.getvalue())

    def test_finish_decline_skips_all_provisioning(self):
        device = make_device("02:00:00:00:00:02")

        plans = self.run_flow([device], ["1", "d", "f", "n"], ["x", "x"])

        self.assertEqual(len(plans), 1)
        self.assertEqual(self.provision_calls, [])
        self.assertIn("Apply setup to 1 device? [y/N]", self.inputs.prompts)
        self.assertIn("Setup cancelled. No changes were made.", self.output.getvalue())
        self.assertNotIn("Setup completed.", self.output.getvalue())

    def test_finish_reports_protocol_error_without_retrying_device(self):
        device = make_device("02:00:00:00:00:02")
        calls = []

        def fail_once(plan, selected):
            calls.append((plan.mac, selected.mac))
            raise RuntimeError("DevInit.account failed: ErrorNotAllowed")

        run_setup(
            [device],
            input_fn=InputSequence(["1", "d", "f", "y"]),
            password_fn=PasswordSequence(["secret-runtime", "secret-runtime"]),
            rescan_fn=lambda: [device],
            output=self.output,
            interactive=False,
            provision_fn=fail_once,
        )

        output = self.output.getvalue()
        self.assertEqual(calls, [(device.mac, device.mac)])
        self.assertIn("Setup failed for 02:00:00:00:00:02: DevInit.account failed: ErrorNotAllowed", output)
        self.assertNotIn("secret-runtime", output)
        self.assertNotIn("Setup completed.", output)

    def test_cancel_without_plans_exits_immediately(self):
        plans = self.run_flow([], ["q"])

        self.assertEqual(plans, [])
        self.assertIn("Setup cancelled.", self.output.getvalue())
        self.assertNotIn("Discard", self.output.getvalue())

    def test_pages_keep_scan_numbers_stable(self):
        devices = [
            make_device(f"00:11:22:33:{index // 256:02x}:{index % 256:02x}")
            for index in range(1, 21)
        ]
        rediscovered = make_device(
            devices[4].mac, init=3734, ip="10.42.0.172"
        )

        plans = self.run_flow(
            devices,
            ["n", "5", "d", "f", "y"],
            ["x", "x"],
            rescans=[[rediscovered]],
            terminal_size=(70, 15),
        )

        self.assertEqual(plans[0].mac, devices[4].mac)
        output = self.output.getvalue()
        self.assertIn("Page 1/5", output)
        self.assertIn("Page 2/5", output)
        self.assertIn("[n] Next   [b] Previous", output)
        self.assertIn("[1-4] Select device", output)
        self.assertIn("[5-8] Select device", output)

    def test_all_twenty_devices_fit_and_navigation_is_omitted(self):
        devices = [
            make_device(f"00:11:22:33:{index // 256:02x}:{index % 256:02x}")
            for index in range(1, 21)
        ]

        self.run_flow(devices, ["f"], terminal_size=(100, 30))

        output = self.output.getvalue()
        self.assertIn("[1-20] Select device", output)
        self.assertNotIn("Page ", output)
        self.assertNotIn("[n] Next", output)
        self.assertNotIn("[b] Previous", output)

    def test_terminal_resize_recalculates_page_size_on_redraw(self):
        devices = [
            make_device(f"00:11:22:33:{index // 256:02x}:{index % 256:02x}")
            for index in range(1, 21)
        ]
        output = io.StringIO()

        with patch(
            "dh_tux_initialize.setup.shutil.get_terminal_size",
            side_effect=((100, 15), (100, 21)),
        ) as get_terminal_size:
            run_setup(
                devices,
                input_fn=InputSequence(["n", "f"]),
                output=output,
                interactive=True,
            )

        rendered = output.getvalue()
        self.assertEqual(get_terminal_size.call_count, 2)
        self.assertIn("Page 1/5", rendered)
        self.assertIn("[1-4] Select device", rendered)
        self.assertIn("Page 2/2", rendered)
        self.assertIn("[11-20] Select device", rendered)

    def test_non_tty_uses_fallback_page_size(self):
        devices = [
            make_device(f"00:11:22:33:{index // 256:02x}:{index % 256:02x}")
            for index in range(1, 21)
        ]
        output = io.StringIO()

        run_setup(
            devices,
            input_fn=InputSequence(["n", "f"]),
            output=output,
            interactive=False,
        )

        rendered = output.getvalue()
        self.assertIn("Page 1/3", rendered)
        self.assertIn("[1-9] Select device", rendered)
        self.assertIn("Page 2/3", rendered)
        self.assertIn("[10-18] Select device", rendered)

    def test_selection_hint_uses_visible_range_for_fewer_devices_than_page_size(self):
        devices = [make_device(f"00:11:22:33:44:{index:02x}") for index in range(1, 4)]

        self.run_flow(devices, ["f"])

        self.assertIn("[1-3] Select device", self.output.getvalue())

    def test_selection_hint_uses_full_page_range(self):
        devices = [make_device(f"00:11:22:33:44:{index:02x}") for index in range(1, 5)]

        self.run_flow(devices, ["f"], terminal_size=(100, 16))

        self.assertIn("[1-4] Select device", self.output.getvalue())

    def test_selection_hint_uses_global_range_on_last_partial_page(self):
        devices = [
            make_device(f"00:11:22:33:{index // 256:02x}:{index % 256:02x}")
            for index in range(1, 15)
        ]

        self.run_flow(devices, ["n", "f"], terminal_size=(100, 21))

        output = self.output.getvalue()
        self.assertIn("Page 2/2", output)
        self.assertIn("[11-14] Select device", output)
        last_page = output.rsplit("Page 2/2", 1)[1]
        self.assertIn("[b] Previous", last_page)
        self.assertNotIn("[n] Next", last_page)

    def test_empty_device_list_omits_selection_action(self):
        self.run_flow([], ["f"])

        self.assertNotIn("Select device", self.output.getvalue())

    def test_mixed_scan_shows_all_devices_and_status_counts(self):
        devices = [
            make_device("02:00:00:00:00:31", 3733, model="Uninitialized-Cam"),
            make_device("02:00:00:00:00:32", 3734, model="Initialized-Cam"),
            make_device("02:00:00:00:00:33", 3732, model="Legacy-Cam"),
            make_device("02:00:00:00:00:34", None, model="Unknown-Cam"),
        ]

        self.run_flow(devices, ["f"])

        output = self.output.getvalue()
        self.assertIn(
            "Found 4 devices: 1 uninitialized, 1 initialized, 1 legacy, 1 unknown.",
            output,
        )
        for model in ("Uninitialized-Cam", "Initialized-Cam", "Legacy-Cam", "Unknown-Cam"):
            self.assertIn(model, output)
        self.assertIn("Uninitialized", output)
        self.assertIn("Initialized", output)
        self.assertIn("Legacy", output)
        self.assertIn("Unknown", output)

    def test_nonprovisionable_devices_remain_visible_but_cannot_be_planned(self):
        initialized = make_device("02:00:00:00:00:02", 3734)

        plans = self.run_flow([initialized], ["1", "f"])

        self.assertEqual(plans, [])
        self.assertIn("IPC-Test", self.output.getvalue())
        self.assertIn(
            "This device is already initialized and cannot be provisioned.",
            self.output.getvalue(),
        )

    def test_fallback_only_endpoint_is_never_provisionable(self):
        fallback = DiscoveredDevice(
            {
                "Mac": "02:00:00:00:00:09",
                "DeviceType": "ONVIF-Model",
                "IPv4Address": {"IPAddress": "192.0.2.77"},
                "Init": 1,
                "DiscoveryMethod": "rpc2-login-challenge",
            },
            {},
            "192.0.2.77",
            identity_sources={
                "model": "onvif-get-device-information",
                "mac": "onvif-wsd-scope",
            },
            dahua_verified=True,
            vendor_evidence=frozenset({"rpc2-login-challenge"}),
        )

        plans = self.run_flow([fallback], ["1", "f"])

        self.assertFalse(fallback.provisionable)
        self.assertEqual(plans, [])
        self.assertIn("ONVIF-Model", self.output.getvalue())
        self.assertIn(
            "This endpoint has no valid DHIP identity and cannot be provisioned.",
            self.output.getvalue(),
        )

    def test_narrow_terminal_hides_plan_before_core_device_columns(self):
        device = make_device("02:00:00:00:00:02")
        rediscovered = make_device(
            device.mac, init=3734, ip="10.42.0.172"
        )

        self.run_flow(
            [device],
            ["1", "d", "f", "y"],
            ["x", "x"],
            rescans=[[rediscovered]],
            terminal_size=(50, 24),
        )

        table_headers = [
            line for line in self.output.getvalue().splitlines() if line.startswith("No.")
        ]
        self.assertGreaterEqual(len(table_headers), 2)
        self.assertIn("Model", table_headers[-1])
        self.assertIn("MAC", table_headers[-1])
        self.assertIn("Current IP", table_headers[-1])
        self.assertNotIn("Plan", table_headers[-1])

    def test_all_devices_are_shown_and_only_uninitialized_can_be_planned(self):
        initialized = make_device("02:00:00:00:00:02", 3734)
        uninitialized = make_device("02:00:00:00:00:03", 3733)
        rediscovered = make_device(
            uninitialized.mac, init=3734, ip="10.42.0.172"
        )

        plans = self.run_flow(
            [initialized, uninitialized],
            ["1", "2", "d", "f", "y"],
            ["x", "x"],
            rescans=[[rediscovered]],
        )

        self.assertEqual([plan.mac for plan in plans], [uninitialized.mac])
        self.assertIn("This device is already initialized and cannot be provisioned.", self.output.getvalue())

    def test_ctrl_c_is_a_clean_abort(self):
        device = make_device("02:00:00:00:00:02")

        def interrupt(_prompt):
            raise KeyboardInterrupt

        plans = run_setup([device], input_fn=interrupt, output=self.output, interactive=False)

        self.assertEqual(plans, [])
        self.assertIn("Aborted.", self.output.getvalue())


if __name__ == "__main__":
    unittest.main()
