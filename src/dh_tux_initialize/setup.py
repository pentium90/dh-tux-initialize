"""Interactive camera setup planning and explicit Finish execution."""

from __future__ import annotations

import ipaddress
import shutil
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from typing import TextIO

from .discovery import DiscoveredDevice
from .password import read_password
from .provisioning import ProvisioningError, provision_device, validate_network_plan

USERNAME = "admin"
_DETAIL_RULE = "─" * 39
_SUMMARY_RULE = "─" * 61


class SetupPlan:
    """A prepared configuration tied to a device's MAC address.

    The password is retained for a future execution phase, but is deliberately
    excluded from repr and from the explicit JSON-safe representation.
    """

    __slots__ = ("mac", "model", "username", "_password", "network_mode", "ipv4", "netmask", "gateway")

    def __init__(
        self,
        *,
        mac: str,
        model: str,
        password: str,
        network_mode: str,
        ipv4: str | None = None,
        netmask: str | None = None,
        gateway: str | None = None,
    ) -> None:
        self.mac = mac
        self.model = model
        self.username = USERNAME
        self._password = password
        self.network_mode = network_mode
        self.ipv4 = ipv4
        self.netmask = netmask
        self.gateway = gateway

    @property
    def password(self) -> str:
        """Return the secret for internal use by a later execution phase."""
        return self._password

    def to_json_dict(self) -> dict[str, str | None]:
        """Return display-safe plan data, never including credentials."""
        return {
            "mac": self.mac,
            "model": self.model,
            "username": self.username,
            "network_mode": self.network_mode,
            "ipv4": self.ipv4,
            "netmask": self.netmask,
            "gateway": self.gateway,
        }

    def __repr__(self) -> str:
        return (
            f"SetupPlan(mac={self.mac!r}, model={self.model!r}, "
            f"username={self.username!r}, network_mode={self.network_mode!r}, "
            f"ipv4={self.ipv4!r}, netmask={self.netmask!r}, gateway={self.gateway!r})"
        )


ScanFunction = Callable[[], Sequence[DiscoveredDevice]]
ProvisionFunction = Callable[[SetupPlan, DiscoveredDevice], None]
TerminalSizeFunction = Callable[[], object]
_FALLBACK_PAGE_SIZE = 9
_NETWORK_REDISCOVERY_TIMEOUT = 8.0
_NETWORK_REDISCOVERY_INTERVAL = 0.5


def run_setup(
    devices: Sequence[DiscoveredDevice],
    *,
    show_all: bool = False,
    input_fn: Callable[[str], str] = input,
    password_fn: Callable[[str], str] = read_password,
    rescan_fn: ScanFunction | None = None,
    output: TextIO | None = None,
    terminal_size_fn: TerminalSizeFunction | None = None,
    interactive: bool | None = None,
    provision_fn: ProvisionFunction | None = None,
) -> list[SetupPlan]:
    """Run setup planning, then apply saved plans when the user confirms Finish.

    Quick rescans replace the current snapshot while setup plans remain keyed by
    MAC. The legacy ``show_all`` argument is retained for callers; every scan
    displays all devices.
    """
    stream = output if output is not None else sys.stdout
    if interactive is None:
        interactive = input_fn is input and _stream_is_tty(stream) and _stream_is_tty(sys.stdin)

    current_devices = list(devices)
    plans: list[SetupPlan] = []
    plan_devices: dict[str, DiscoveredDevice] = {}
    scan_notice = _scan_result(current_devices)
    action_notice: list[str] | None = None
    page = 0

    try:
        while True:
            visible_devices = list(current_devices)
            if terminal_size_fn is not None:
                columns, lines = _terminal_dimensions(terminal_size_fn)
                page_size, page_count = _device_page_layout(
                    visible_devices,
                    terminal_lines=lines,
                    action_notice=action_notice,
                )
            elif interactive:
                columns, lines = _terminal_dimensions(
                    lambda: shutil.get_terminal_size(fallback=(80, 24))
                )
                page_size, page_count = _device_page_layout(
                    visible_devices,
                    terminal_lines=lines,
                    action_notice=action_notice,
                )
            else:
                columns = 80
                page_size = _FALLBACK_PAGE_SIZE
                page_count = max(
                    1, (len(visible_devices) + page_size - 1) // page_size
                )
            page = min(page, page_count - 1)

            _render_main_screen(
                visible_devices,
                plans,
                page=page,
                page_size=page_size,
                page_count=page_count,
                terminal_columns=columns,
                scan_notice=scan_notice,
                action_notice=action_notice,
                output=stream,
                clear=interactive,
            )
            choice = input_fn("> ").strip().casefold()
            action_notice = None

            if choice in {"f", "finish"}:
                print_summary(plans, stream)
                if plans:
                    errors = _finish_preflight(plans, plan_devices, rescan_fn)
                    if errors:
                        for plan, message in errors:
                            print(f"Setup failed for {plan.mac}: {message}", file=stream)
                        return plans
                    noun = "device" if len(plans) == 1 else "devices"
                    confirmation = input_fn(
                        f"Apply setup to {len(plans)} {noun}? [y/N]"
                    ).strip().casefold()
                    if confirmation not in {"y", "yes"}:
                        print("Setup cancelled. No changes were made.", file=stream)
                        return plans
                    _finish_plans(
                        plans,
                        plan_devices,
                        provision_fn=provision_fn,
                        rescan_fn=rescan_fn,
                        output=stream,
                    )
                return plans

            if choice in {"q", "quit"}:
                if not plans:
                    print("Setup cancelled.", file=stream)
                    return []
                noun = "plan" if len(plans) == 1 else "plans"
                answer = input_fn(
                    f"Discard {len(plans)} setup {noun} and quit? [y/N]: "
                ).strip().casefold()
                if answer in {"y", "yes"}:
                    print("Setup cancelled. Plans discarded.", file=stream)
                    return []
                action_notice = ["Cancel declined. Setup plans are still available."]
                continue

            if choice == "r":
                if rescan_fn is None:
                    action_notice = ["Rescan is unavailable."]
                    continue
                print("Scanning for Dahua devices...", file=stream, flush=True)
                try:
                    current_devices = list(rescan_fn())
                    rediscovered = {
                        _mac_key(mac): device
                        for device in current_devices
                        if (mac := _device_mac(device)) is not None
                    }
                    for plan in plans:
                        key = _mac_key(plan.mac)
                        if key in rediscovered:
                            plan_devices[key] = rediscovered[key]
                    scan_notice = _scan_result(current_devices)
                    page = 0
                except (OSError, ValueError) as exc:
                    scan_notice = f"DHIP scan failed: {exc}"
                continue

            if choice in {"l", "p"}:
                _show_plans(
                    plans,
                    plan_devices,
                    input_fn=input_fn,
                    password_fn=password_fn,
                    output=stream,
                    interactive=interactive,
                )
                continue

            if choice == "n" and page + 1 < page_count:
                page += 1
                continue
            if choice == "b" and page > 0:
                page -= 1
                continue

            try:
                number = int(choice)
            except ValueError:
                controls = ["r"]
                if page_count > 1:
                    if page + 1 < page_count:
                        controls.append("n")
                    if page > 0:
                        controls.append("b")
                controls.extend(("p", "f", "q"))
                choices = ", ".join(controls[:-1]) + f", or {controls[-1]}"
                action_notice = [f"Choose a device number, {choices}."]
                continue

            page_start = page * page_size
            page_end = min(page_start + page_size, len(visible_devices))
            if number < page_start + 1 or number > page_end:
                action_notice = ["Select a device shown on the current page."]
                continue

            device = visible_devices[number - 1]
            if not device.provisionable:
                action_notice = _nonprovisionable_notice(device)
                continue
            mac = _device_mac(device)

            key = _mac_key(mac)
            existing_plan = _find_plan(plans, key)
            if existing_plan is not None:
                result = _manage_existing_plan(
                    existing_plan,
                    device,
                    input_fn=input_fn,
                    password_fn=password_fn,
                    output=stream,
                    interactive=interactive,
                )
                if result == "delete":
                    plans.remove(existing_plan)
                    plan_devices.pop(key, None)
                    action_notice = ["Setup plan deleted."]
                elif isinstance(result, SetupPlan):
                    plans[plans.index(existing_plan)] = result
                    plan_devices[key] = device
                    action_notice = _saved_plan_notice(result, updated=True)
                continue

            plan = _configure_device(
                device,
                input_fn=input_fn,
                password_fn=password_fn,
                output=stream,
                interactive=interactive,
            )
            if plan is not None:
                plans.append(plan)
                plan_devices[key] = device
                action_notice = _saved_plan_notice(plan)
    except KeyboardInterrupt:
        print("Aborted.", file=stream)
        return []
    except EOFError:
        print("Input ended. Setup cancelled.", file=stream)
        return []


def _scan_result(devices: Sequence[DiscoveredDevice]) -> str:
    counts = {
        status: sum(device.initialization_status == status for device in devices)
        for status in ("Uninitialized", "Initialized", "Legacy", "Unknown")
    }
    device_label = "device" if len(devices) == 1 else "devices"
    summary = [
        f"{counts['Uninitialized']} uninitialized",
        f"{counts['Initialized']} initialized",
    ]
    if counts["Legacy"]:
        summary.append(f"{counts['Legacy']} legacy")
    summary.append(f"{counts['Unknown']} unknown")
    return f"Found {len(devices)} {device_label}: {', '.join(summary)}."


def _terminal_dimensions(size_fn: TerminalSizeFunction) -> tuple[int, int]:
    try:
        size = size_fn()
        if hasattr(size, "columns") and hasattr(size, "lines"):
            return int(size.columns), int(size.lines)
        columns, lines = size  # type: ignore[misc]
        return int(columns), int(lines)
    except (OSError, TypeError, ValueError):
        return 80, 24


def _device_page_layout(
    devices: Sequence[DiscoveredDevice],
    *,
    terminal_lines: int,
    action_notice: Sequence[str] | None,
) -> tuple[int, int]:
    """Return a page size that leaves the table header, menu, and prompt visible."""
    if not devices:
        return 1, 1

    # Rows outside the device body: title, spacing, scan summary, optional action
    # and empty-state notices, table header and rule, menu, and input prompt.
    fixed_rows = 4
    if action_notice:
        fixed_rows += 1 + len(action_notice)
    if not any(device.initialization_status == "Uninitialized" for device in devices):
        fixed_rows += 2
    fixed_rows += 1  # blank line before the table
    fixed_rows += 2  # table header and separator
    fixed_rows += 1  # blank line after the table
    fixed_rows += 1  # menu
    fixed_rows += 1  # input prompt

    without_navigation = max(0, terminal_lines - fixed_rows)
    if len(devices) <= without_navigation:
        return max(1, len(devices)), 1

    with_navigation = max(1, terminal_lines - fixed_rows - 1)
    page_count = (len(devices) + with_navigation - 1) // with_navigation
    return with_navigation, page_count


def _stream_is_tty(stream: TextIO) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, OSError, ValueError):
        return False


def _selection_hint(numbers: Sequence[int]) -> str:
    """Format only the device numbers visible on the current page."""
    if not numbers:
        return ""
    if len(numbers) == 1:
        return f"[{numbers[0]}] Select device"
    return f"[{numbers[0]}-{numbers[-1]}] Select device"


def _nonprovisionable_notice(device: DiscoveredDevice) -> list[str]:
    if not device.valid_dhip_identity:
        return ["This endpoint has no valid DHIP identity and cannot be provisioned."]
    status = device.initialization_status
    if status == "Initialized":
        return ["This device is already initialized and cannot be provisioned."]
    if status == "Legacy":
        return ["This legacy device does not support initialization."]
    if status == "Uninitialized" and not _device_mac(device):
        return ["This device has no MAC address and cannot be selected."]
    return ["This device's initialization status is unknown and it cannot be provisioned."]


def _clear_screen(output: TextIO, enabled: bool) -> None:
    if enabled:
        output.write("\x1b[2J\x1b[H")
        output.flush()


def _render_main_screen(
    devices: Sequence[DiscoveredDevice],
    plans: Sequence[SetupPlan],
    *,
    page: int,
    page_size: int,
    page_count: int,
    terminal_columns: int,
    scan_notice: str,
    action_notice: Sequence[str] | None,
    output: TextIO,
    clear: bool,
) -> None:
    _clear_screen(output, clear)
    print("DH-Tux-Initialize", file=output)
    print(file=output)
    print("Dahua devices", file=output)
    print(scan_notice, file=output)
    if action_notice:
        print(file=output)
        for line in action_notice:
            print(line, file=output)

    page_start = page * page_size
    page_devices = devices[page_start : page_start + page_size]
    if not any(device.initialization_status == "Uninitialized" for device in devices):
        print(file=output)
        print("No uninitialized devices found.", file=output)
    if devices:
        print(file=output)
        _print_device_table(
            devices,
            page_devices,
            start_number=page_start + 1,
            plans=plans,
            terminal_columns=terminal_columns,
            output=output,
        )
    print(file=output)

    if page_count > 1:
        page_controls = []
        if page + 1 < page_count:
            page_controls.append("[n] Next")
        if page > 0:
            page_controls.append("[b] Previous")
        print(f"Page {page + 1}/{page_count}   {'   '.join(page_controls)}", file=output)

    selectable_numbers = [
        page_start + offset + 1 for offset, _device in enumerate(page_devices)
    ]
    select_hint = _selection_hint(selectable_numbers)
    menu_parts = [select_hint, "[r] Rescan"]
    menu_parts.extend(("[p] Plans", "[f] Finish", "[q] Cancel"))
    print("   ".join(menu_parts), file=output)


def _print_device_table(
    all_devices: Sequence[DiscoveredDevice],
    page_devices: Sequence[DiscoveredDevice],
    *,
    start_number: int,
    plans: Sequence[SetupPlan],
    terminal_columns: int,
    output: TextIO,
) -> None:
    plan_by_mac = {_mac_key(plan.mac): plan for plan in plans}
    all_rows = [
        _device_row(index, device, plan_by_mac)
        for index, device in enumerate(all_devices, start=1)
    ]
    columns = ["No.", "Model", "MAC", "Current IP", "Status"]
    if plans:
        columns.append("Plan")

    visible_columns = list(range(len(columns)))
    widths = _column_widths(columns, all_rows)
    if _table_width(widths) > terminal_columns and "Plan" in columns:
        visible_columns.remove(columns.index("Plan"))
    if _table_width([widths[index] for index in visible_columns]) > terminal_columns and "Status" in columns:
        visible_columns.remove(columns.index("Status"))

    labels = [columns[index] for index in visible_columns]
    visible_widths = [widths[index] for index in visible_columns]
    print(_format_table_row(labels, visible_widths), file=output)
    print("  ".join("─" * width for width in visible_widths), file=output)
    for index, device in enumerate(page_devices, start=start_number):
        row = _device_row(index, device, plan_by_mac)
        values = [row[column_index] for column_index in visible_columns]
        print(_format_table_row(values, visible_widths), file=output)


def _device_row(
    number: int,
    device: DiscoveredDevice,
    plan_by_mac: Mapping[str, SetupPlan],
) -> list[str]:
    mac = _display_value(device.mac)
    plan = (
        plan_by_mac.get(_mac_key(mac))
        if mac != "—" and device.initialization_status == "Uninitialized"
        else None
    )
    plan_label = "—" if plan is None else ("DHCP" if plan.network_mode == "dhcp" else "Static")
    return [
        str(number),
        _display_value(device.model),
        mac,
        _display_value(device.ipv4),
        device.initialization_status,
        plan_label,
    ]


def _column_widths(columns: Sequence[str], rows: Sequence[Sequence[str]]) -> list[int]:
    return [max(len(columns[index]), *(len(row[index]) for row in rows)) for index in range(len(columns))]


def _table_width(widths: Sequence[int]) -> int:
    return sum(widths) + 2 * max(0, len(widths) - 1)


def _format_table_row(values: Sequence[str], widths: Sequence[int]) -> str:
    return "  ".join(
        value.ljust(widths[index]) if index < len(values) - 1 else value
        for index, value in enumerate(values)
    )


def _configure_device(
    device: DiscoveredDevice,
    *,
    input_fn: Callable[[str], str],
    password_fn: Callable[[str], str],
    output: TextIO,
    interactive: bool,
) -> SetupPlan | None:
    _clear_screen(output, interactive)
    _print_device_details(device, output)
    print(file=output)
    print("Network configuration", file=output)

    while True:
        print("[d] DHCP", file=output)
        print("[s] Static IPv4", file=output)
        print("[b] Back", file=output)
        choice = input_fn("> ").strip().casefold()
        if choice in {"d", "dhcp"}:
            mode = "dhcp"
            ipv4 = netmask = gateway = None
            break
        if choice in {"s", "static"}:
            values = _read_static_network(device, input_fn, output)
            if values == "back" or values == "abort":
                return None
            ipv4, netmask, gateway = values
            mode = "static"
            break
        if choice in {"b", "back"}:
            return None
        print("Choose d, s, or b.", file=output)

    password = _read_matching_password(password_fn, output)
    return SetupPlan(
        mac=_device_mac(device) or "",
        model=_display_value(device.model),
        password=password,
        network_mode=mode,
        ipv4=ipv4,
        netmask=netmask,
        gateway=gateway,
    )


def _print_device_details(device: DiscoveredDevice, output: TextIO) -> None:
    print("Device", file=output)
    print(_DETAIL_RULE, file=output)
    print(f"Model:       {_display_value(device.model)}", file=output)
    print(f"MAC:         {_display_value(device.mac)}", file=output)
    print(f"Current IP:  {_display_value(device.ipv4)}", file=output)
    print(f"Serial:      {_display_value(device.serial_number)}", file=output)
    print(f"Firmware:    {_display_value(device.firmware)}", file=output)


def _network_defaults(device: DiscoveredDevice) -> tuple[str | None, str | None]:
    containers: list[Mapping[str, object]] = [device.info]
    for key, value in device.info.items():
        if key.casefold() in {"ipv4address", "ipv4addressinfo"} and isinstance(value, Mapping):
            containers.insert(0, value)
    subnet_mask = _first_mapping_value(
        containers,
        {"subnetmask", "subnetmaskv4", "netmask", "mask", "submask"},
    )
    gateway = _first_mapping_value(
        containers,
        {"defaultgateway", "defaultgatewayv4", "gateway", "gatewayip"},
    )
    return subnet_mask, gateway


def _first_mapping_value(
    containers: Sequence[Mapping[str, object]], names: set[str]
) -> str | None:
    for container in containers:
        for key, value in container.items():
            if key.casefold() in names and value not in (None, ""):
                return str(value)
    return None


def _read_static_network(
    device: DiscoveredDevice,
    input_fn: Callable[[str], str],
    output: TextIO,
) -> tuple[str, str, str] | str:
    default_mask, default_gateway = _network_defaults(device)
    while True:
        address = _read_ipv4_field(input_fn, output, "IP address", _valid_host_address)
        if address in {"back", "abort"}:
            return address
        mask = _read_ipv4_field(
            input_fn, output, "Subnet mask", _valid_netmask, default=default_mask
        )
        if mask in {"back", "abort"}:
            return mask
        gateway = _read_ipv4_field(
            input_fn, output, "Gateway", _valid_host_address, default=default_gateway
        )
        if gateway in {"back", "abort"}:
            return gateway

        ip_address = ipaddress.IPv4Address(address)
        network = ipaddress.IPv4Network(f"{ip_address}/{mask}", strict=False)
        gateway_address = ipaddress.IPv4Address(gateway)
        if ip_address == gateway_address:
            print("IP address and gateway must be different.", file=output)
            continue
        if gateway_address not in network:
            print("Gateway and IP address must be on the same network.", file=output)
            continue
        if network.prefixlen < 31 and (
            ip_address in {network.network_address, network.broadcast_address}
            or gateway_address in {network.network_address, network.broadcast_address}
        ):
            print("IP address and gateway must be valid host addresses.", file=output)
            continue
        return str(ip_address), str(network.netmask), str(gateway_address)


def _read_ipv4_field(
    input_fn: Callable[[str], str],
    output: TextIO,
    label: str,
    validator: Callable[[str], str],
    *,
    default: str | None = None,
) -> str:
    while True:
        default_text = f" [{default}]" if default else ""
        raw = input_fn(f"{label}{default_text}: ").strip()
        command = raw.casefold()
        if command in {"b", "back"}:
            return "back"
        if command in {"q", "quit"}:
            return "abort"
        if not raw and default:
            raw = default
        try:
            return validator(raw)
        except ValueError as exc:
            print(f"Invalid {label}: {exc}", file=output)


def _valid_host_address(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("only IPv4 is allowed")
    return str(address)


def _valid_netmask(value: str) -> str:
    address = ipaddress.ip_address(value)
    if not isinstance(address, ipaddress.IPv4Address):
        raise ValueError("only an IPv4 subnet mask is allowed")
    try:
        network = ipaddress.IPv4Network(f"0.0.0.0/{address}")
    except (ipaddress.NetmaskValueError, ipaddress.AddressValueError) as exc:
        raise ValueError("not a contiguous subnet mask") from exc
    return str(network.netmask)


def _read_matching_password(
    password_fn: Callable[[str], str], output: TextIO
) -> str:
    while True:
        first = password_fn("Admin password: ")
        second = password_fn("Confirm admin password: ")
        if not first:
            print("Password cannot be empty.", file=output)
            continue
        if first != second:
            print("Passwords do not match. Please try again.", file=output)
            continue
        return first


def _saved_plan_notice(plan: SetupPlan, *, updated: bool = False) -> list[str]:
    lines = ["Setup plan updated." if updated else "Setup plan saved.", "", plan.model]
    lines.append(f"Network: {'DHCP' if plan.network_mode == 'dhcp' else 'Static'}")
    if plan.network_mode == "static":
        lines.extend([f"IP:      {plan.ipv4}", f"Mask:    {plan.netmask}", f"Gateway: {plan.gateway}"])
    return lines


def _manage_existing_plan(
    plan: SetupPlan,
    device: DiscoveredDevice,
    *,
    input_fn: Callable[[str], str],
    password_fn: Callable[[str], str],
    output: TextIO,
    interactive: bool,
) -> SetupPlan | str:
    _clear_screen(output, interactive)
    print("A setup plan already exists for this device.", file=output)
    print("[e] Edit   [d] Delete plan   [b] Back", file=output)
    choice = input_fn("> ").strip().casefold()
    if choice in {"d", "delete"}:
        return "delete"
    if choice in {"e", "edit"}:
        return _configure_device(
            device,
            input_fn=input_fn,
            password_fn=password_fn,
            output=output,
            interactive=interactive,
        ) or "back"
    return "back"


def _show_plans(
    plans: list[SetupPlan],
    plan_devices: dict[str, DiscoveredDevice],
    *,
    input_fn: Callable[[str], str],
    password_fn: Callable[[str], str],
    output: TextIO,
    interactive: bool,
) -> None:
    notice: list[str] | None = None
    while True:
        _clear_screen(output, interactive)
        print_plan_list(plans, output, notice=notice)
        print("[number] Manage plan   [b] Back", file=output)
        choice = input_fn("> ").strip().casefold()
        notice = None
        if choice in {"b", "back"}:
            return
        try:
            number = int(choice)
        except ValueError:
            notice = ["Enter a plan number or b."]
            continue
        if number < 1 or number > len(plans):
            notice = ["That plan number does not exist."]
            continue

        plan = plans[number - 1]
        key = _mac_key(plan.mac)
        device = plan_devices[key]
        result = _manage_existing_plan(
            plan,
            device,
            input_fn=input_fn,
            password_fn=password_fn,
            output=output,
            interactive=interactive,
        )
        if result == "delete":
            plans.remove(plan)
            plan_devices.pop(key, None)
            notice = ["Setup plan deleted."]
        elif isinstance(result, SetupPlan):
            plans[number - 1] = result
            notice = _saved_plan_notice(result, updated=True)


def print_plan_list(
    plans: Sequence[SetupPlan], output: TextIO, *, notice: Sequence[str] | None = None
) -> None:
    print("Planned setup", file=output)
    print(_SUMMARY_RULE, file=output)
    if notice:
        print(file=output)
        for line in notice:
            print(line, file=output)
    if not plans:
        print("No setup plans yet.", file=output)
        return
    for index, plan in enumerate(plans, start=1):
        network = "DHCP" if plan.network_mode == "dhcp" else "Static"
        print(f"{index}  {plan.model}  {plan.mac}  {network}", file=output)


def print_summary(plans: Sequence[SetupPlan], output: TextIO) -> None:
    print("Planned setup", file=output)
    print(_SUMMARY_RULE, file=output)
    if not plans:
        print("No setup plans.", file=output)
    for index, plan in enumerate(plans, start=1):
        print(f"{index}  {plan.model}  {plan.mac}", file=output)
        print("   Admin password: configured", file=output)
        if plan.network_mode == "dhcp":
            print("   Network: DHCP", file=output)
        else:
            print("   Network: Static", file=output)
            print(f"   IP:      {plan.ipv4}", file=output)
            print(f"   Mask:    {plan.netmask}", file=output)
            print(f"   Gateway: {plan.gateway}", file=output)
        if index < len(plans):
            print(file=output)
    if plans:
        print(file=output)


def _finish_preflight(
    plans: Sequence[SetupPlan],
    plan_devices: Mapping[str, DiscoveredDevice],
    rescan_fn: ScanFunction | None,
) -> list[tuple[SetupPlan, str]]:
    errors: list[tuple[SetupPlan, str]] = []
    for plan in plans:
        try:
            validate_network_plan(plan)
        except ProvisioningError as exc:
            errors.append((plan, str(exc)))
            continue
        device = plan_devices.get(_mac_key(plan.mac))
        if device is None:
            errors.append((plan, "camera is no longer in the discovered inventory"))
        elif not device.provisionable:
            errors.append((plan, "camera is no longer uninitialized"))
    if rescan_fn is None:
        errors.extend(
            (plan, "rediscovery is unavailable; no changes were made")
            for plan in plans
            if all(existing is not plan for existing, _message in errors)
        )
    return errors


def _finish_plans(
    plans: Sequence[SetupPlan],
    plan_devices: Mapping[str, DiscoveredDevice],
    *,
    provision_fn: ProvisionFunction | None,
    rescan_fn: ScanFunction,
    output: TextIO,
) -> None:
    active_provision_fn = provision_fn
    if active_provision_fn is None:
        active_provision_fn = lambda plan, device: provision_device(
            plan,
            device,
            rediscover_fn=rescan_fn,
        )
    discovered_results: list[DiscoveredDevice] = []
    failed = False
    dhcp_ip_not_discovered = False
    static_ip_not_discovered = False
    for plan in plans:
        device = plan_devices[_mac_key(plan.mac)]
        try:
            old_ip = str(device.ipv4)
            active_provision_fn(plan, device)
            if plan.network_mode == "dhcp":
                rediscovered = _wait_for_new_dhcp_address(
                    plan.mac,
                    old_ip,
                    rescan_fn,
                )
                if rediscovered is None:
                    # DHDiscover.setConfig already succeeded. A delayed DHCP
                    # lease must not turn the completed write into a failure.
                    dhcp_ip_not_discovered = True
                    continue
            else:
                target_ip = str(ipaddress.IPv4Address(plan.ipv4.strip()))
                rediscovered = _wait_for_static_address(
                    plan.mac,
                    target_ip,
                    rescan_fn,
                )
                if rediscovered is None:
                    static_ip_not_discovered = True
                    continue
            discovered_results.append(rediscovered)
        except Exception as exc:
            message = _safe_provision_error(exc, plan.password)
            print(f"Setup failed for {plan.mac}: {message}", file=output)
            failed = True
    if not failed:
        if not static_ip_not_discovered:
            print("Setup completed.", file=output)
        if dhcp_ip_not_discovered:
            if static_ip_not_discovered:
                print("DHCP configuration applied.", file=output)
            print("Device initialized and DHCP enabled.", file=output)
            print("New IP not discovered yet.", file=output)
        if static_ip_not_discovered:
            print("Static configuration applied.", file=output)
            print("Configured IP not rediscovered yet.", file=output)
    for device in discovered_results:
        print(
            f"{_display_value(device.model)}  {_display_value(device.mac)}  "
            f"{_display_value(device.ipv4)}  {device.initialization_status}",
            file=output,
        )


def _wait_for_new_dhcp_address(
    mac: str,
    old_ip: str,
    rescan_fn: ScanFunction,
) -> DiscoveredDevice | None:
    """Rediscover the same MAC until DHCP gives it an address other than its old IP."""
    deadline = time.monotonic() + _NETWORK_REDISCOVERY_TIMEOUT
    mac_key = _mac_key(mac)
    while True:
        try:
            current_devices = list(rescan_fn())
        except (OSError, ValueError):
            current_devices = []
        rediscovered = next(
            (
                candidate
                for candidate in current_devices
                if _device_mac(candidate) is not None
                and _mac_key(_device_mac(candidate) or "") == mac_key
                and candidate.ipv4 not in (None, "")
                and str(candidate.ipv4) != old_ip
            ),
            None,
        )
        if rediscovered is not None:
            return rediscovered

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(_NETWORK_REDISCOVERY_INTERVAL, remaining))


def _wait_for_static_address(
    mac: str,
    target_ip: str,
    rescan_fn: ScanFunction,
) -> DiscoveredDevice | None:
    """Rediscover the same MAC at the exact address requested by its static plan."""
    deadline = time.monotonic() + _NETWORK_REDISCOVERY_TIMEOUT
    mac_key = _mac_key(mac)
    while True:
        try:
            current_devices = list(rescan_fn())
        except (OSError, ValueError):
            current_devices = []
        rediscovered = next(
            (
                candidate
                for candidate in current_devices
                if _device_mac(candidate) is not None
                and _mac_key(_device_mac(candidate) or "") == mac_key
                and candidate.ipv4 not in (None, "")
                and str(candidate.ipv4) == target_ip
            ),
            None,
        )
        if rediscovered is not None:
            return rediscovered

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return None
        time.sleep(min(_NETWORK_REDISCOVERY_INTERVAL, remaining))


def _safe_provision_error(exc: Exception, password: str) -> str:
    message = str(exc)
    if password:
        message = message.replace(password, "<redacted>")
    return message or exc.__class__.__name__


def _find_plan(plans: Sequence[SetupPlan], mac_key: str) -> SetupPlan | None:
    return next((plan for plan in plans if _mac_key(plan.mac) == mac_key), None)


def _device_mac(device: DiscoveredDevice) -> str | None:
    return str(device.mac).strip() if device.mac not in (None, "") else None


def _mac_key(mac: str) -> str:
    return mac.strip().casefold()


def _display_value(value: object) -> str:
    return "—" if value is None or value == "" else str(value)
