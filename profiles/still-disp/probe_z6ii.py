"""Bounded version-locked per-engine QEMU probes; never contact camera hardware."""
import argparse
import hashlib
import json
import os
import re
from pathlib import Path
import socket
import subprocess
import sys
import time
import traceback
import xml.etree.ElementTree as ET

from host_env import ROOT, WORK
from run_evidence import ProcessLedger
from mcu_wire_contract import validate_bus
from meaningful_qemu_log import MeaningfulQemuLog

sys.path.insert(0, str(WORK / "tools"))
from interactive import QMP, free_port
from rsp import Remote

OUT = ROOT / "results/standalone-probe"


def peer_data_layout(manifest):
    """Bind cold RAM extent to the selected, hash-verified model source.

    Historical fixed models keep their observed 1MiB section. The cold123
    repair adds the next observed section, without expanding domain0.
    """
    name = "nikon-z6ii.c"
    path = manifest.get("immutable_model_sources", {}).get(name)
    if not path:
        raise ValueError("Selected binary has no immutable peer data model")
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest["z6ii_sources"][name]:
        raise ValueError("Selected peer data model snapshot identity changed")
    match = re.search(rb"#define\s+Z6II_PEER_DATA_SECTION_BYTES\s+UINT32_C\((0x[0-9a-fA-F]+)\)", data)
    if match:
        size = int(match[1], 16)
        if size != 0x200000:
            raise ValueError("Unsupported immutable peer data extent")
        return size
    # Legacy selection is explicit: a missing constant alone is insufficient.
    if (b'"z6ii-observed-master-data-section", 0x100000, RAM_SHARED' in data and
            b'Observed peer data must be a run-local1MiB RAM file' in data):
        return 0x100000
    raise ValueError("Selected model has no recognized peer data extent")


def peer_parameter_layout(manifest):
    """Read layout from the selected immutable binary's verified model source.

    Historical binaries retain their 2MiB layout. New builds share the full
    original application pool, including the existing DMA view.
    """
    name = "nikon-z6ii-peer-parameter.h"
    path = manifest.get("immutable_model_sources", {}).get(name)
    if not path:
        raise ValueError("Selected binary has no peer parameter model")
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != manifest["z6ii_sources"][name]:
        raise ValueError("Selected parameter model snapshot identity changed")
    def constant(key, required=True):
        match = re.search(rb"#define\s+" + key.encode() + rb"\s+UINT32_C\((0x[0-9a-fA-F]+)\)", data)
        if not match:
            if required:
                raise ValueError("Selected model lacks " + key)
            return None
        return int(match[1], 16)
    size = constant("Z6II_PARAMETER_SECTION_BYTES")
    offset = constant("Z6II_PARAMETER_DMA_VIEW_OFFSET", False)
    if size not in (0x200000, 0x4300000) or (offset is not None and offset != 0x400000):
        raise ValueError("Unsupported immutable parameter pool layout")
    return size, offset


class Probe:
    def __init__(self, role, label, cpus=2, protocol_diagnostic=False, assisted=False,
                 link_test_peer=False, graphics_capture=False, shared_queue=None,
                 coupled_notifications=False, automatic_peer_irq=False, link_configuration=False,
                 coupled_gpio=False, gpio_connection=False, coupled_phy=False, coupled_stop=False,
                 coupled_lanes=False, natural_boot_board=False, icount_shift=6,
                 peer_buffer_section=None, peer_data_section=None, peer_dma_section=None, slave_dma_section=None,
                 slave_fill_channel1=False, master_fill_channel1=False, exmcu_transport=False, exmcu_packet=None,
                 exmcu_packet_delay_ms=0, exmcu_sys_version_packet=None,
                 exmcu_sys_state_packet=None, exmcu_sys_delay_ms=1000,
                 exmcu_key_packet=None, exmcu_key_delay_ms=2000,
                 exmcu_power_packet=None, exmcu_power_delay_ms=3000,
                 exmcu_service0d_packet=None, exmcu_service0d_delay_ms=10,
                 exmcu_service0d_command01_packet=None, exmcu_service0d_command01_delay_ms=10,
                 slave_2b20_control_latch=False, slave_pipeline_mode=None,
                 shared_event_poll_ns=1000, slave_access_ready_line=False, slave_sdhci_mode=None,
                 slave_filesystem="FAT16", slave_card_capacity_mib=256, persistent_input_spec=None,
                 build_manifest=None, qemu_exception_trace=False,
                 mcu_wire_path=None, mcu_wire_poll_ns=None, mcu_wire_known_wait_ms=None,
                 peer_parameter_section=None, parameter_require_recorded_body=False,
                 parameter_source_reference_spec=None,
                 source50_tcg_trace=False, boot_tcg_trace=False, debugger_byte_ledger=False, output_directory=None):
        manifest_path = Path(build_manifest).resolve(strict=True) if build_manifest else WORK / "z6ii/build-manifest.json"
        manifest_bytes = manifest_path.read_bytes()
        self.manifest = json.loads(manifest_bytes)
        if source50_tcg_trace and (role != "master" or not natural_boot_board or
                not self.manifest.get("source50_TCG_observer", {}).get("installed")):
            raise ValueError("Source50 TCG trace requires the reviewed original master model")
        if boot_tcg_trace and (role != "master" or not natural_boot_board or
                not self.manifest.get("boot_TCG_observer", {}).get("installed")):
            raise ValueError("Boot TCG evidence requires the reviewed original master model")
        parameter_size, dma_view_offset = peer_parameter_layout(self.manifest) if peer_parameter_section is not None else (None, None)
        if mcu_wire_path is not None:
            if not (role == "master" and natural_boot_board) or exmcu_transport or any((
                    exmcu_packet, exmcu_sys_version_packet, exmcu_sys_state_packet,
                    exmcu_key_packet, exmcu_power_packet, exmcu_service0d_packet,
                    exmcu_service0d_command01_packet)):
                raise ValueError("Native MCU wire requires original master boot and cannot mix with EXMCU replay")
            if not isinstance(mcu_wire_poll_ns, int) or not 1 <= mcu_wire_poll_ns <= 1000000:
                raise ValueError("Native MCU wire requires an explicit poll quantum from1 to1000000ns")
            mcu_wire_path = validate_bus(mcu_wire_path, self.manifest)
            if mcu_wire_known_wait_ms is not None and (
                    not isinstance(mcu_wire_known_wait_ms, int) or not 0 <= mcu_wire_known_wait_ms <= 5000):
                raise ValueError("MCU known-state host wait requires an explicit0..5000ms budget")
        elif mcu_wire_poll_ns is not None:
            raise ValueError("MCU poll quantum without an explicit live bus")
        elif mcu_wire_known_wait_ms is not None:
            raise ValueError("MCU known-state host wait without an explicit live bus")
        if slave_card_capacity_mib not in (256, 4096):
            raise ValueError("Virtual SD capacity must be256 or4096MiB")
        if slave_filesystem not in ("FAT16", "FAT32") or (slave_filesystem != "FAT16" and slave_sdhci_mode != "fat-card"):
            raise ValueError("FAT filesystem selection requires formatted virtual cards")
        if slave_sdhci_mode is not None and (slave_sdhci_mode not in ("no-card", "empty-card", "fat-card") or
                                             not slave_access_ready_line):
            raise ValueError("Slave SDHCI hypothesis requires enabled bridge access and explicit card mode")
        if slave_access_ready_line and slave_pipeline_mode != "complete":
            raise ValueError("Slave access line hypothesis requires completed bridge model")
        if shared_event_poll_ns not in (1000, 10000, 100000) or (
                shared_event_poll_ns != 1000 and not automatic_peer_irq):
            raise ValueError("Shared-event poll hypothesis requires automatic IRQ and1/10/100us")
        if slave_pipeline_mode is not None and (slave_pipeline_mode not in ("config", "complete") or
                role != "slave" or not natural_boot_board or not slave_2b20_control_latch):
            raise ValueError("Pipeline hypothesis requires original slave/control latch and config/complete mode")
        if slave_2b20_control_latch and (role != "slave" or not natural_boot_board):
            raise ValueError("Control300 latch hypothesis requires the integrated original slave")
        if not isinstance(exmcu_packet_delay_ms, int) or not 0 <= exmcu_packet_delay_ms <= 5000:
            raise ValueError("EX MCU packet arrival hypothesis must be0..5000ms")
        if exmcu_transport and not (natural_boot_board and role == "master"):
            raise ValueError("EX MCU transport requires the explicit master natural boot board")
        if exmcu_packet is not None:
            if not exmcu_transport:
                raise ValueError("Original MCU replay packet requires explicit device transport")
            exmcu_packet = Path(exmcu_packet).resolve(strict=True)
            if hashlib.sha256(exmcu_packet.read_bytes()).hexdigest() != (
                    "77b609bb95f21cbf40666862ee1c7e94120d24362192860528812aeae2081a42"):
                raise ValueError("Original EX1850 replay packet identity mismatch")
        if not isinstance(exmcu_sys_delay_ms, int) or not 0 <= exmcu_sys_delay_ms <= 5000:
            raise ValueError("SYS response timing hypothesis must be0..5000ms")
        if exmcu_sys_state_packet is not None and exmcu_sys_version_packet is None:
            raise ValueError("SYS C-initialized input requires original SYS version response")
        for path, sha in ((exmcu_sys_version_packet,
                "cdfdfa0ff6c6d330cc0d6afca9c811998153c64abe2a961f52d4b69844f7d8a1"),
                (exmcu_sys_state_packet,
                "10aaf044134c791bd486afbb4ed7973e4a9c67f2adc1f016372477a96055dd25")):
            if path is not None:
                if not exmcu_transport:
                    raise ValueError("Original SYS packet requires explicit MCU device transport")
                if hashlib.sha256(Path(path).read_bytes()).hexdigest() != sha:
                    raise ValueError("Original SYS serializer packet identity mismatch")
        key_level = None
        if not isinstance(exmcu_key_delay_ms, int) or not 0 <= exmcu_key_delay_ms <= 5000:
            raise ValueError("GPIO-sampled KEY input delay must be0..5000ms")
        if exmcu_key_packet is not None:
            if not exmcu_transport:
                raise ValueError("GPIO-sampled KEY input requires explicit MCU device transport")
            exmcu_key_packet = Path(exmcu_key_packet).resolve(strict=True)
            sha = hashlib.sha256(exmcu_key_packet.read_bytes()).hexdigest()
            identities = {
                "e719378f4a32e6a7bf5b59f47f85a03cf669c8dfecab2a5e312119930ad670ac": "high",
                "625c01b8135dc9d714e6b231c1ad5ff758c7156d92ded21d7e4de46a51bf8458": "low",
            }
            if sha not in identities:
                raise ValueError("Original GPIO-sampled KEY packet identity mismatch")
            key_level = identities[sha]
            origin = json.loads((exmcu_key_packet.parent / "结果.json").read_text())
            if not (origin.get("passed") and origin.get("source_and_ROM_unchanged") and
                    origin.get("source_sha256") == "4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1" and
                    origin.get("packet", {}).get("sha256") == sha and
                    origin.get("pin_level_hypothesis") == key_level and
                    origin.get("ADC_failure_substituted") is False and
                    origin.get("full_native_MCU_boot_verified") is False):
                raise ValueError("GPIO-sampled KEY input requires its matching bounded-origin evidence")
        if not isinstance(exmcu_power_delay_ms, int) or not 0 <= exmcu_power_delay_ms <= 5000:
            raise ValueError("C-initialized power report delay hypothesis must be0..5000ms")
        if exmcu_power_packet is not None:
            if not exmcu_transport:
                raise ValueError("C-initialized power report requires explicit MCU device transport")
            exmcu_power_packet = Path(exmcu_power_packet).resolve(strict=True)
            sha = hashlib.sha256(exmcu_power_packet.read_bytes()).hexdigest()
            if sha != "15601ea6879781609e45e607b2f055315836506e33d3a2b2889c9fbe34cd55f2":
                raise ValueError("Original C-initialized power report packet identity mismatch")
            origin = json.loads((exmcu_power_packet.parent / "结果.json").read_text())
            if not (origin.get("passed") and origin.get("source_and_ROM_unchanged") and
                    origin.get("source_sha256") == "4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1" and
                    origin.get("packet", {}).get("sha256") == sha and
                    origin.get("source_power_state_unchanged") and
                    origin.get("host_RAM_fixtures") == [] and
                    origin.get("ready_or_success_flag_fixtures") == [] and
                    origin.get("physical_power_sampling_executed") is False and
                    origin.get("full_native_MCU_boot_verified") is False and
                    origin.get("initialization", {}).get("CPU_model_readback_matches_request") is True and
                    origin.get("initialization", {}).get("CPU_model_id") == 9):
                raise ValueError("C-initialized power input requires its matching bounded-origin evidence")
        if not isinstance(exmcu_service0d_delay_ms, int) or not 0 <= exmcu_service0d_delay_ms <= 5000:
            raise ValueError("Native service0D GPIO reply delay hypothesis must be0..5000ms")
        if exmcu_service0d_packet is not None:
            if not exmcu_transport:
                raise ValueError("Native GPIO reply requires explicit MCU device transport")
            exmcu_service0d_packet = Path(exmcu_service0d_packet).resolve(strict=True)
            sha = hashlib.sha256(exmcu_service0d_packet.read_bytes()).hexdigest()
            if sha != "a1b460698e1895650d541220dea57ef01e701fd653deb0499748d407eb73ec83":
                raise ValueError("Original service0D GPIO wire82 reply identity mismatch")
            origin = json.loads((exmcu_service0d_packet.parent / "结果.json").read_text())
            packet_origin = origin.get("packet", {})
            expected_request = "01ee6699bdde0435350399d545d95d957181a88ca1cd8dbe2f29a6388b79004d"
            fixtures = origin.get("host_RAM_fixtures", [])
            if not (origin.get("passed") and origin.get("source_and_ROM_unchanged") and
                    origin.get("source_sha256") == "4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1" and
                    origin.get("completion_result_supplied") is False and
                    origin.get("ready_or_success_flag_fixtures") == [] and
                    origin.get("full_native_MCU_boot_verified") is False and
                    origin.get("physical_GPIO_effect_verified") is False and
                    origin.get("RTOS_mutex_initialized") is False and
                    origin.get("native_lock_API_error_replaced") is False and
                    origin.get("native_lock_API_return") == "0xffffffee" and
                    origin.get("native_worker_result") == "00" and
                    origin.get("third_original_event") == dict(object="0x20013d48", flags="0x10") and
                    len(fixtures) == 1 and fixtures[0].get("sha256") == expected_request and
                    packet_origin.get("sha256") == sha and packet_origin.get("wire_command") == 0x82 and
                    packet_origin.get("host_selected_completion_result") is False and
                    origin.get("initialization", {}).get("CPU_model_id") == 9 and
                    origin.get("initialization", {}).get("CPU_model_readback_matches_request") is True and
                    any(row.get("address") == "0x40021418" and row.get("value") == "0x10000000"
                        for row in origin.get("hardware_accesses", []))):
                raise ValueError("Service0D reply requires its matching original worker, GPIO and retained lock-error evidence")
            frozen_probe = exmcu_service0d_packet.parent / "probe-source.py"
            if hashlib.sha256(frozen_probe.read_bytes()).hexdigest() != origin.get("script_sha256"):
                raise ValueError("Service0D original diagnostic source snapshot identity mismatch")
        if not isinstance(exmcu_service0d_command01_delay_ms, int) or not 0 <= exmcu_service0d_command01_delay_ms <= 5000:
            raise ValueError("Original command01 reply delay hypothesis must be0..5000ms")
        if exmcu_service0d_command01_packet is not None:
            if exmcu_service0d_packet is None:
                raise ValueError("Original command01 reply requires the preceding original wire82 input")
            exmcu_service0d_command01_packet = Path(exmcu_service0d_command01_packet).resolve(strict=True)
            sha = hashlib.sha256(exmcu_service0d_command01_packet.read_bytes()).hexdigest()
            if sha != "e26040542afb1efe1d3871c5135e365d1fdc60a1d440c3fc80a94d7a0f02995c":
                raise ValueError("Original command01 wire81 packet identity mismatch")
            origin = json.loads((exmcu_service0d_command01_packet.parent / "结果.json").read_text())
            fixtures = origin.get("host_RAM_fixtures", [])
            packet_origin = origin.get("packet", {})
            expected = "e9ba210be8296467ef14030b2cd91f8c34cd4d71c3ca1aa3c3867e2af6d2a677"
            if not (origin.get("passed") and origin.get("source_and_ROM_unchanged") and
                    origin.get("source_sha256") == "4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1" and
                    origin.get("full_native_MCU_boot_verified") is False and
                    origin.get("completion_result_supplied") is False and
                    origin.get("host_selected_worker_state") is False and
                    origin.get("ready_or_success_flag_fixtures") == [] and
                    origin.get("worker_initialization_phase_CPU_argument") == 1 and
                    origin.get("worker_initialization_phase_natural_caller_verified") is False and
                    origin.get("TIM_initialization_tail_executed") is True and
                    origin.get("native_timer_handle", {}).get("base") == "0x40001800" and
                    origin.get("worker_state_after_original_initializer") == "03" and
                    origin.get("native_worker_result") == "00" and
                    origin.get("native_worker_completion_callback") == "0x8030f71" and
                    origin.get("third_original_event") == dict(object="0x20013d48", flags="0x8") and
                    origin.get("RTOS_mutex_initialized") is False and
                    origin.get("native_lock_API_error_replaced") is False and
                    origin.get("native_lock_API_return") == "0xffffffee" and
                    origin.get("initialization", {}).get("CPU_model_id") == 9 and
                    origin.get("initialization", {}).get("CPU_model_readback_matches_request") is True and
                    len(fixtures) == 1 and fixtures[0].get("sha256") == expected and
                    packet_origin.get("sha256") == sha and packet_origin.get("wire_command") == 0x81 and
                    packet_origin.get("sequence") == 2 and
                    packet_origin.get("host_selected_completion_result") is False and
                    packet_origin.get("host_selected_worker_state") is False and
                    packet_origin.get("hardware_completion_supplied") is False):
                raise ValueError("Command01 replay requires matching original initialized worker and retained lock-error evidence")
            frozen_probe = exmcu_service0d_command01_packet.parent / "probe-source.py"
            if hashlib.sha256(frozen_probe.read_bytes()).hexdigest() != origin.get("script_sha256"):
                raise ValueError("Command01 diagnostic source snapshot identity mismatch")
        if not isinstance(icount_shift, int) or not 0 <= icount_shift <= 8:
            raise ValueError("Instruction timing hypothesis must use an icount shift from 0 to 8")
        if peer_buffer_section is not None:
            if not natural_boot_board:
                raise ValueError("Observed peer data section requires the explicit integrated boot board")
            peer_buffer_section = Path(peer_buffer_section).resolve(strict=True)
            if peer_buffer_section.stat().st_size != 0x100000:
                raise ValueError("Observed peer section is exactly1MiB run-local RAM")
        if peer_data_section is not None:
            if peer_buffer_section is None or not natural_boot_board:
                raise ValueError("Observed peer data requires integrated original two-guest buffers")
            peer_data_section = Path(peer_data_section).resolve(strict=True)
            if peer_data_section.stat().st_size != peer_data_layout(self.manifest):
                raise ValueError("Observed peer data extent differs from selected immutable model")
        if peer_dma_section is not None:
            if peer_data_section is None or not natural_boot_board:
                raise ValueError("Observed peer DMA source requires integrated original data sections")
            peer_dma_section = Path(peer_dma_section).resolve(strict=True)
            same_pool = peer_parameter_section is not None and peer_dma_section == Path(peer_parameter_section).resolve(strict=True)
            expected_size = parameter_size if same_pool and dma_view_offset is not None else 0x100000
            if peer_dma_section.stat().st_size != expected_size:
                raise ValueError("Observed peer DMA backing differs from the selected model extent")
            if peer_parameter_section is not None and dma_view_offset is not None and not same_pool:
                raise ValueError("Overlapping DMA and parameter pool require one backing file")
        if slave_dma_section is not None:
            if peer_dma_section is None or not natural_boot_board:
                raise ValueError("Observed slave DMA buffer requires integrated original peer DMA")
            slave_dma_section = Path(slave_dma_section).resolve(strict=True)
            if slave_dma_section.stat().st_size != 0x300000:
                raise ValueError("Observed slave DMA buffer is exactly3MiB run-local RAM")
        if peer_parameter_section is not None:
            if peer_data_section is None or not natural_boot_board:
                raise ValueError("Peer parameters require integrated original peer data")
            peer_parameter_section = Path(peer_parameter_section).resolve(strict=True)
            if not peer_parameter_section.is_file() or peer_parameter_section.stat().st_size != parameter_size:
                raise ValueError("Peer parameter extent differs from selected immutable model")
        if parameter_require_recorded_body:
            if peer_parameter_section is None:
                raise ValueError("Recorded body provenance guard needs the shared parameter pool")
            model = Path(self.manifest['immutable_model_sources']['nikon-z6ii.c']).read_text()
            if 'Z6II_PARAMETER_REQUIRE_RECORDED_BODY' not in model:
                raise ValueError("Selected immutable binary has no recorded-body source guard")
        parameter_reference, parameter_reference_environment = None, {}
        if parameter_source_reference_spec is not None:
            if not parameter_require_recorded_body:
                raise ValueError("Read-only parameter references require the source guard")
            from parameter_source_reference import inspect_spec
            parameter_reference, parameter_reference_environment = inspect_spec(
                parameter_source_reference_spec, self.manifest)
        if slave_fill_channel1 and (role != "slave" or peer_dma_section is None or slave_sdhci_mode is None):
            raise ValueError("Original slave fill channel1 requires its observed DMA source and storage model")
        if master_fill_channel1 and (role != "master" or not natural_boot_board):
            raise ValueError("Original master fill channel1 requires the integrated original master")
        if natural_boot_board and not (shared_queue is not None and coupled_notifications):
            raise ValueError("Integrated boot board requires two-ended shared queues and notifications")
        if natural_boot_board and (assisted or link_test_peer):
            raise ValueError("Integrated boot board cannot enable the older scripted peer")
        if coupled_lanes and not coupled_stop:
            raise ValueError("Lane idle hypothesis requires explicit coupled stop notification")
        if coupled_stop and not coupled_phy:
            raise ValueError("Coupled stop notification requires the explicit two-ended startup hypothesis")
        if coupled_gpio and not (coupled_notifications and link_configuration):
            raise ValueError("GPIO semantics require the explicit coupled notification/configuration model")
        if gpio_connection and not coupled_gpio:
            raise ValueError("Candidate GPIO connection requires explicit GPIO semantics")
        if coupled_phy and not (gpio_connection and automatic_peer_irq):
            raise ValueError("Two-ended startup hypothesis requires candidate wire and automatic original ISR delivery")
        if link_configuration and shared_queue is None:
            raise ValueError("Coupled link configuration requires explicit shared backing")
        if automatic_peer_irq and not coupled_notifications:
            raise ValueError("Automatic peer IRQ requires the explicit notification model")
        if coupled_notifications and shared_queue is None:
            raise ValueError("Coupled notifications require the explicit shared queue backing")
        if role not in ("master", "slave"):
            raise ValueError("Unknown Z6II engine role")
        if shared_queue is not None and (assisted or link_test_peer):
            raise ValueError("Coupled queue board cannot silently enable assisted/scripted peripherals")
        if shared_queue is not None:
            shared_queue = Path(shared_queue).resolve(strict=True)
        if link_test_peer and not assisted:
            raise ValueError("Scripted link peer requires the explicit assisted board")
        self.role = role
        self.directory = Path(output_directory).resolve() if output_directory is not None else (
            OUT / (time.strftime("%Y%m%d-%H%M%S") + "-" + role + "-" + label))
        self.directory.mkdir(parents=True, exist_ok=False)
        self.process_ledger = ProcessLedger(self.directory, role)
        if peer_parameter_section is not None and "nikon-z6ii-peer-parameter.h" not in self.manifest.get("immutable_model_sources", {}):
            raise ValueError("Selected binary does not declare the peer parameter copy model")
        binary = Path(self.manifest["binary"])
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == self.manifest["binary_sha256"]
        self.blob = (ROOT / f"inputs/firmware/{role}-original-with-crc.bin").read_bytes()
        self.persistent_input = None
        if persistent_input_spec is not None:
            if not (assisted or natural_boot_board):
                raise ValueError("Persistent input requires a board with external flash devices")
            from persistent_input import prepare
            self.persistent_input = prepare(persistent_input_spec, role, self.directory)
        self.report = {"role": role, "label": label, "camera_access": False,
                       "persistent_flash_input": self.persistent_input,
                       "instruction_bytes_modified": False, "register_or_ram_fixture": False,
                       "icount_shift_hypothesis": icount_shift,
                       "observed_peer_buffer_section": str(peer_buffer_section) if peer_buffer_section else None,
                       "observed_peer_data_section": str(peer_data_section) if peer_data_section else None,
                       "observed_peer_DMA_section": str(peer_dma_section) if peer_dma_section else None,
                       "observed_slave_DMA_section": str(slave_dma_section) if slave_dma_section else None,
                       "observed_peer_parameter_section": str(peer_parameter_section) if peer_parameter_section else None,
                       "peer_parameter_pool_bytes": parameter_size,
                       "peer_DMA_shared_pool_offset": dma_view_offset if peer_parameter_section else None,
                       "peer_parameter_physical_mapping_verified": False,
                       "peer_parameter_copy_timing_physically_verified": False,
                       "parameter_source_read_only_reference": parameter_reference,
                       "slave_fill_channel1_hypothesis": slave_fill_channel1,
                       "master_fill_channel1_hypothesis": master_fill_channel1,
                       "build": self.manifest, "events": [], "cpus": cpus,
                       "build_manifest_path": str(manifest_path),
                       "build_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                       "QEMU_exception_trace_enabled": bool(qemu_exception_trace),
                       "protocol_diagnostic_board": protocol_diagnostic or assisted or shared_queue is not None,
                       "coupled_queue_board": shared_queue is not None,
                       "coupled_notifications_board": coupled_notifications,
                       "automatic_peer_irq": automatic_peer_irq,
                       "coupled_link_configuration": link_configuration,
                       "coupled_GPIO_semantics": coupled_gpio, "candidate_GPIO_connection": gpio_connection,
                       "coupled_PHY_startup_hypothesis": coupled_phy,
                       "coupled_stop_notification_hypothesis": coupled_stop,
                       "coupled_lane_idle_hypothesis": coupled_lanes,
                       "functional_devices_hypothesis": assisted,
                       "integrated_natural_boot_board": natural_boot_board,
                       "integrated_functional_devices_hypothesis": natural_boot_board,
                       "slave_2B200300_control_latch_reset0_hypothesis": slave_2b20_control_latch,
                       "slave_pipeline_mode_hypothesis": slave_pipeline_mode,
                       "slave_pipeline_physical_semantics_verified": False,
                       "shared_event_poll_ns_hypothesis": shared_event_poll_ns,
                       "slave_access_ready_line_hypothesis": slave_access_ready_line,
                       "slave_SDHCI_mode_hypothesis": slave_sdhci_mode,
                       "slave_SDHCI_physical_semantics_verified": False,
                       "slave_2B200300_physical_semantics_verified": False,
                       "scripted_link_test_peer": link_test_peer,
                       "other_engine_firmware_executed_by_test_peer": False}
        self.report.update(EX_MCU_transport_hypothesis=exmcu_transport,
                           EX_MCU_original_packet_replay=str(exmcu_packet) if exmcu_packet else None,
                           EX_MCU_packet_arrival_delay_ms_hypothesis=exmcu_packet_delay_ms,
                           EX_MCU_SYS_version_packet=str(exmcu_sys_version_packet) if exmcu_sys_version_packet else None,
                           EX_MCU_SYS_C_initialized_packet=str(exmcu_sys_state_packet) if exmcu_sys_state_packet else None,
                           EX_MCU_SYS_response_delay_ms_hypothesis=exmcu_sys_delay_ms,
                           EX_MCU_SYS_physical_state_sampling_executed=False,
                           EX_MCU_GPIO_sampled_KEY_packet=str(exmcu_key_packet) if exmcu_key_packet else None,
                           EX_MCU_KEY_pin_level_hypothesis=key_level,
                           EX_MCU_KEY_arrival_delay_ms_hypothesis=exmcu_key_delay_ms,
                           EX_MCU_KEY_physical_pin_levels_measured=False,
                           EX_MCU_C_initialized_power_packet=str(exmcu_power_packet) if exmcu_power_packet else None,
                           EX_MCU_power_arrival_delay_ms_hypothesis=exmcu_power_delay_ms,
                           EX_MCU_power_physical_sampling_executed=False,
                           EX_MCU_service0D_native_GPIO_reply=str(exmcu_service0d_packet) if exmcu_service0d_packet else None,
                           EX_MCU_service0D_reply_delay_ms_hypothesis=exmcu_service0d_delay_ms,
                           EX_MCU_service0D_reply_only_exact_sequence1=True if exmcu_service0d_packet else None,
                           EX_MCU_service0D_physical_GPIO_effect_verified=False,
                           EX_MCU_service0D_original_lock_error_retained=True if exmcu_service0d_packet else None,
                           EX_MCU_service0D_command01_packet=str(exmcu_service0d_command01_packet) if exmcu_service0d_command01_packet else None,
                           EX_MCU_service0D_command01_reply_delay_ms_hypothesis=exmcu_service0d_command01_delay_ms,
                           EX_MCU_service0D_command01_only_exact_sequence2=True if exmcu_service0d_command01_packet else None,
                           EX_MCU_service0D_command01_MCU_init_phase1_is_diagnostic=True,
                           EX_MCU_service0D_command01_phase_natural_caller_verified=False,
                           EX_MCU_full_firmware_executed=False,
                           EX_MCU_native_wire_path=str(mcu_wire_path) if mcu_wire_path else None,
                           EX_MCU_native_wire_poll_ns_hypothesis=mcu_wire_poll_ns,
                           EX_MCU_known_state_host_wait_ms_hypothesis=mcu_wire_known_wait_ms,
                           EX_MCU_host_causality_experiment=bool(mcu_wire_known_wait_ms),
                           EX_MCU_known_state_physical_latency_verified=False,
                           EX_MCU_native_wire_physical_pairing_verified=False,
                           EX_MCU_native_wire_relative_clocks_synchronized=False)
        port, qmp = free_port(), free_port()
        model = "nikon-z6ii-" + role + ("-boot" if natural_boot_board else
                                      "-coupled-notify" if coupled_notifications else
                                      "-coupled" if shared_queue is not None else
                                      "-assisted" if assisted else "-protocol" if protocol_diagnostic else "")
        command = [str(binary), "-M", model, "-smp", str(cpus),
                   "-display", "none", "-monitor", "none", "-serial", "none", "-nic", "none",
                   "-bios", str(ROOT / f"inputs/firmware/{role}-original-with-crc.bin")]
        self.report["virtual_SD_cards"] = []
        if slave_sdhci_mode in ("empty-card", "fat-card"):
            from virtual_sd import create
            for channel in range(2):
                medium = self.directory / f"fresh-{slave_sdhci_mode}-sd-host{channel}.raw"
                info = create(medium, formatted=slave_sdhci_mode == "fat-card", filesystem=slave_filesystem,
                              capacity_bytes=slave_card_capacity_mib * 1024 * 1024)
                command.extend(("-drive", f"if=none,id=z6ii_slave_sd{channel},format=raw,file={medium}"))
                self.report["virtual_SD_cards"].append(dict(info, host=channel))
        for cpu in range(cpus):
            command.extend(["-device", f"loader,addr=0x10020000,cpu-num={cpu}"])
        command.extend(["-S", "-gdb", f"tcp:127.0.0.1:{port}", "-qmp",
                        f"tcp:127.0.0.1:{qmp},server=on,wait=off", "-accel", "tcg",
                        "-icount", f"shift={icount_shift},align=off,sleep=off"])
        if qemu_exception_trace:
            trace_path = self.directory / "qemu.log"
            command.extend(["-d", "int,guest_errors", "-D", "/dev/fd/1"])
            self.report["QEMU_exception_trace_path"] = str(trace_path)
            self.report["QEMU_exception_trace_selectively_retained"] = True
        self.report["command"] = command
        self.log = MeaningfulQemuLog(self.directory / "qemu.log")
        self.remote = self.monitor = None
        self.process = None
        self.debugger_ledgers = {}
        self.running = False
        self.started = time.monotonic()
        try:
            env = dict(os.environ, Z6_VERIFY_CPSR_HFLAGS="1")
            for name in tuple(env):
                if name.startswith(("Z6II_SOURCE50_TCG_", "Z6II_BOOT_TCG_")): env.pop(name)
            self.report["source50_TCG_trace_enabled"] = bool(source50_tcg_trace)
            if source50_tcg_trace:
                trace = self.directory / "qemu.log"
                env.update(Z6II_SOURCE50_TCG_TRACE="1",
                           Z6II_SOURCE50_TCG_TRACE_ROLE="master")
                self.report["source50_TCG_trace_path"] = str(trace)
                self.report["source50_TCG_trace_selectively_retained"] = True
            self.report["boot_TCG_trace_enabled"] = bool(boot_tcg_trace)
            if boot_tcg_trace:
                saiso_focus = env.get("Z6II_BOOT_SAISO_FOCUS") == "1"
                other_focus = any(env.get(name) == "1" for name in (
                    "Z6II_BOOT_ERROR_ONLY", "Z6II_BOOT_STARTUP_FOCUS",
                    "Z6II_BOOT_CAPTG_ONLY", "Z6II_BOOT_CAPSEQ_ONLY",
                    "Z6II_BOOT_MANAGER_FOCUS", "Z6II_BOOT_MANAGER_DATE_TIER"))
                saiso_contract = self.manifest.get("boot_TCG_observer", {}).get("saiso_focus", {})
                if not saiso_focus or other_focus or not saiso_contract:
                    raise ValueError("The local adapter requires the frozen SAISO observation alone")
                trace = self.directory / "original-saiso-observation.log"
                env.update(Z6II_BOOT_TCG_TRACE="1", Z6II_BOOT_TCG_TRACE_ROLE=role,
                           Z6II_BOOT_TCG_TRACE_OUT=str(trace))
                self.report["boot_TCG_trace_path"] = str(trace)
                self.report["boot_TCG_trace_selectively_retained"] = True
                self.report["boot_TCG_saiso_focus"] = True
                self.report["boot_TCG_saiso_retention"] = dict(saiso_contract,
                    enabled=True, direct_bounded_log=True, host_log_sampling=False,
                    adapter_path=str(Path(__file__).resolve()),
                    adapter_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
            # A caller must select a live endpoint explicitly. Inheriting a
            # previous shell's wire variables must not change the baseline.
            for name in ("Z6II_MCU_WIRE_PATH", "Z6II_MCU_WIRE_PAIRING", "Z6II_MCU_WIRE_POLL_NS",
                         "Z6II_MCU_WIRE_KNOWN_WAIT_MS"):
                env.pop(name, None)
            if mcu_wire_path:
                for name in list(env):
                    if name.startswith("Z6II_EXMCU_"):
                        env.pop(name)
                env.update(Z6II_MCU_WIRE_PATH=str(mcu_wire_path),
                           Z6II_MCU_WIRE_PAIRING="pb14_pd12_pe3_pg6",
                           Z6II_MCU_WIRE_POLL_NS=str(mcu_wire_poll_ns))
                if mcu_wire_known_wait_ms is not None:
                    env["Z6II_MCU_WIRE_KNOWN_WAIT_MS"] = str(mcu_wire_known_wait_ms)
            self.report["TG_event_test_mode"] = env.get("Z6II_TG_EVENT_TEST") if role == "master" else None
            self.report["TG_event_test_is_physical_sensor_model"] = False
            if role != "master":
                env.pop("Z6II_TG_EVENT_TEST", None)
            for name in ("Z6II_PERSISTENT_INPUT_FILE", "Z6II_PERSISTENT_INPUT_BASE", "Z6II_PERSISTENT_INPUT_SHA256"):
                env.pop(name, None)
            if self.persistent_input:
                env.update(Z6II_PERSISTENT_INPUT_FILE=self.persistent_input["snapshot"],
                           Z6II_PERSISTENT_INPUT_BASE=self.persistent_input["base"],
                           Z6II_PERSISTENT_INPUT_SHA256=self.persistent_input["sha256"])
            env.pop("Z6II_LINK_TEST_PEER", None)
            env.pop("Z6II_QUEUE_BACKING", None)
            env.pop("Z6II_QUEUE_ROLE", None)
            env.pop("Z6II_QUEUE_AUTO_IRQ", None)
            env.pop("Z6II_SHARED_EVENT_POLL_NS", None)
            if shared_event_poll_ns != 1000:
                env["Z6II_SHARED_EVENT_POLL_NS"] = str(shared_event_poll_ns)
            env.pop("Z6II_LINK_CONFIGURATION", None)
            env.pop("Z6II_PEER_BUFFER_SECTION", None)
            env.pop("Z6II_PEER_DATA_SECTION", None)
            env.pop("Z6II_PEER_DMA_SECTION", None)
            env.pop("Z6II_SLAVE_DMA_SECTION", None)
            env.pop("Z6II_PEER_PARAMETER_SECTION", None)
            env.pop("Z6II_SLAVE_FILL_CHANNEL1", None)
            env.pop("Z6II_MASTER_FILL_CHANNEL1", None)
            if slave_fill_channel1:
                env["Z6II_SLAVE_FILL_CHANNEL1"] = "1"
            if master_fill_channel1:
                env["Z6II_MASTER_FILL_CHANNEL1"] = "1"
            env.pop("Z6II_SLAVE_2B20_CONTROL_LATCH", None)
            env.pop("Z6II_SLAVE_PIPELINE_MODE", None)
            env.pop("Z6II_SLAVE_ACCESS_READY_LINE", None)
            env.pop("Z6II_SLAVE_SDHCI_MODE", None)
            if slave_sdhci_mode is not None:
                env["Z6II_SLAVE_SDHCI_MODE"] = slave_sdhci_mode
            if slave_access_ready_line:
                env["Z6II_SLAVE_ACCESS_READY_LINE"] = "1"
            if slave_pipeline_mode is not None:
                env["Z6II_SLAVE_PIPELINE_MODE"] = slave_pipeline_mode
            if slave_2b20_control_latch:
                env["Z6II_SLAVE_2B20_CONTROL_LATCH"] = "1"
            env.pop("Z6II_EXMCU_TRANSPORT", None)
            env.pop("Z6II_EXMCU_PACKET", None)
            env.pop("Z6II_EXMCU_PACKET_DELAY_MS", None)
            env.pop("Z6II_EXMCU_PACKET_DUMP", None)
            for key in ("Z6II_EXMCU_SYS_VERSION_PACKET", "Z6II_EXMCU_SYS_STATE_PACKET", "Z6II_EXMCU_SYS_DELAY_MS"):
                env.pop(key, None)
            for key in ("Z6II_EXMCU_KEY_PACKET", "Z6II_EXMCU_KEY_LEVEL", "Z6II_EXMCU_KEY_DELAY_MS"):
                env.pop(key, None)
            for key in ("Z6II_EXMCU_POWER_PACKET", "Z6II_EXMCU_POWER_DELAY_MS"):
                env.pop(key, None)
            for key in ("Z6II_EXMCU_SERVICE0D_PACKET", "Z6II_EXMCU_SERVICE0D_DELAY_MS"):
                env.pop(key, None)
            if exmcu_transport:
                env["Z6II_EXMCU_TRANSPORT"] = "1"
                packets = self.directory / "EXMCU-original-TX-packets"
                packets.mkdir()
                env["Z6II_EXMCU_PACKET_DUMP"] = str(packets)
                self.report["EX_MCU_original_TX_packet_directory"] = str(packets)
            if exmcu_packet is not None:
                env["Z6II_EXMCU_PACKET"] = str(exmcu_packet)
                env["Z6II_EXMCU_PACKET_DELAY_MS"] = str(exmcu_packet_delay_ms)
            if exmcu_sys_version_packet is not None:
                env["Z6II_EXMCU_SYS_VERSION_PACKET"] = str(Path(exmcu_sys_version_packet).resolve())
                env["Z6II_EXMCU_SYS_DELAY_MS"] = str(exmcu_sys_delay_ms)
            if exmcu_sys_state_packet is not None:
                env["Z6II_EXMCU_SYS_STATE_PACKET"] = str(Path(exmcu_sys_state_packet).resolve())
            if exmcu_key_packet is not None:
                env["Z6II_EXMCU_KEY_PACKET"] = str(exmcu_key_packet)
                env["Z6II_EXMCU_KEY_LEVEL"] = key_level
                env["Z6II_EXMCU_KEY_DELAY_MS"] = str(exmcu_key_delay_ms)
            if exmcu_power_packet is not None:
                env["Z6II_EXMCU_POWER_PACKET"] = str(exmcu_power_packet)
                env["Z6II_EXMCU_POWER_DELAY_MS"] = str(exmcu_power_delay_ms)
            if exmcu_service0d_packet is not None:
                env["Z6II_EXMCU_SERVICE0D_PACKET"] = str(exmcu_service0d_packet)
                env["Z6II_EXMCU_SERVICE0D_DELAY_MS"] = str(exmcu_service0d_delay_ms)
            if exmcu_service0d_command01_packet is not None:
                env["Z6II_EXMCU_SERVICE0D_COMMAND01_PACKET"] = str(exmcu_service0d_command01_packet)
                env["Z6II_EXMCU_SERVICE0D_COMMAND01_DELAY_MS"] = str(exmcu_service0d_command01_delay_ms)
            if peer_buffer_section is not None:
                env["Z6II_PEER_BUFFER_SECTION"] = str(peer_buffer_section)
            if peer_data_section is not None:
                env["Z6II_PEER_DATA_SECTION"] = str(peer_data_section)
            if peer_dma_section is not None:
                env["Z6II_PEER_DMA_SECTION"] = str(peer_dma_section)
            if slave_dma_section is not None:
                env["Z6II_SLAVE_DMA_SECTION"] = str(slave_dma_section)
            if peer_parameter_section is not None:
                env["Z6II_PEER_PARAMETER_SECTION"] = str(peer_parameter_section)
            env.pop("Z6II_PARAMETER_REQUIRE_RECORDED_BODY", None)
            env.pop("Z6II_PARAMETER_RECORDED50_REFERENCE", None)
            env.pop("Z6II_PARAMETER_RECORDED47_REFERENCE", None)
            if parameter_require_recorded_body:
                env["Z6II_PARAMETER_REQUIRE_RECORDED_BODY"] = "1"
                env.update(parameter_reference_environment)
            for key in ("Z6II_COUPLED_GPIO", "Z6II_GPIO_CONNECTION", "Z6II_COUPLED_PHY", "Z6II_COUPLED_STOP", "Z6II_COUPLED_LANES"):
                env.pop(key, None)
            if coupled_gpio:
                env["Z6II_COUPLED_GPIO"] = "1"
            if gpio_connection:
                env["Z6II_GPIO_CONNECTION"] = "1"
            if coupled_phy:
                env["Z6II_COUPLED_PHY"] = "1"
            if coupled_stop:
                env["Z6II_COUPLED_STOP"] = "1"
            if coupled_lanes:
                env["Z6II_COUPLED_LANES"] = "1"
            if link_configuration:
                env["Z6II_LINK_CONFIGURATION"] = "1"
            if automatic_peer_irq:
                env["Z6II_QUEUE_AUTO_IRQ"] = "1"
            if shared_queue is not None:
                env.update(Z6II_QUEUE_BACKING=str(shared_queue), Z6II_QUEUE_ROLE=role)
                self.report["shared_queue_backing"] = str(shared_queue)
            if link_test_peer:
                env["Z6II_LINK_TEST_PEER"] = "1"
            if graphics_capture:
                graphics = self.directory / "graphics-uploads"
                graphics.mkdir()
                env["Z6II_GRAPHICS_DUMP_DIR"] = str(graphics)
                self.report["graphics_capture_directory"] = str(graphics)
            self.report["diagnostic_environment"] = {k: env[k] for k in
                ("Z6_VERIFY_CPSR_HFLAGS", "Z6II_LINK_TEST_PEER", "Z6II_DEVICE_TRACE", "Z6II_SENSOR_MMIO_TRACE",
                 "Z6II_PERSISTENT_INPUT_FILE", "Z6II_PERSISTENT_INPUT_BASE", "Z6II_PERSISTENT_INPUT_SHA256",
                 "Z6II_GRAPHICS_DUMP_DIR", "Z6II_QUEUE_BACKING", "Z6II_QUEUE_ROLE",
                 "Z6II_QUEUE_AUTO_IRQ", "Z6II_LINK_CONFIGURATION", "Z6II_COUPLED_GPIO",
                 "Z6II_GPIO_CONNECTION", "Z6II_COUPLED_PHY", "Z6II_COUPLED_STOP", "Z6II_COUPLED_LANES",
                 "Z6II_PEER_BUFFER_SECTION", "Z6II_PEER_DATA_SECTION", "Z6II_PEER_DMA_SECTION", "Z6II_SLAVE_DMA_SECTION",
                 "Z6II_PEER_PARAMETER_SECTION",
                 "Z6II_SLAVE_FILL_CHANNEL1", "Z6II_MASTER_FILL_CHANNEL1", "Z6II_EXMCU_TRANSPORT", "Z6II_EXMCU_PACKET",
                 "Z6II_EXMCU_PACKET_DELAY_MS", "Z6II_EXMCU_PACKET_DUMP",
                 "Z6II_EXMCU_SYS_VERSION_PACKET", "Z6II_EXMCU_SYS_STATE_PACKET",
                 "Z6II_EXMCU_SYS_DELAY_MS", "Z6II_EXMCU_KEY_PACKET",
                 "Z6II_EXMCU_KEY_LEVEL", "Z6II_EXMCU_KEY_DELAY_MS",
                 "Z6II_MCU_WIRE_PATH", "Z6II_MCU_WIRE_PAIRING", "Z6II_MCU_WIRE_POLL_NS",
                 "Z6II_MCU_WIRE_KNOWN_WAIT_MS", "Z6II_SOURCE50_TCG_TRACE",
                 "Z6II_SOURCE50_TCG_TRACE_OUT", "Z6II_SOURCE50_TCG_TRACE_ROLE",
                 "Z6II_BOOT_TCG_TRACE", "Z6II_BOOT_TCG_TRACE_OUT", "Z6II_BOOT_TCG_TRACE_ROLE", "Z6II_BAYER_SOURCE") if k in env}
            self.process_ledger.attempting(command)
            self.process = subprocess.Popen(command, stdout=self.log, stderr=subprocess.STDOUT, env=env)
            self.process_ledger.started(self.process)
            if debugger_byte_ledger:
                from debugger_byte_ledger import ByteLedger, audited_remote, audited_qmp
                scope = f"{role}_EXPEED_debugger_API_connections_only"
                for connection in ("RSP", "QMP"):
                    self.debugger_ledgers[connection] = ByteLedger(self.directory, connection, scope=scope)
                self.remote = audited_remote(Remote)(port, self.debugger_ledgers["RSP"])
            else:
                self.remote = Remote(port)
            self.remote.command("qSupported:multiprocess+;xmlRegisters=arm")
            self.remote.command("qXfer:features:read:target.xml:0,fff")
            self.remote.command("Hg0")
            self.remote.command("?")
            self.remote.sock.settimeout(15)
            self.monitor = audited_qmp(QMP)(qmp, self.debugger_ledgers["QMP"]) if debugger_byte_ledger else QMP(qmp)
            self.threads = []
            answer = self.remote.command("qfThreadInfo")
            while answer.startswith("m"):
                self.threads.extend(answer[1:].split(","))
                answer = self.remote.command("qsThreadInfo")
            assert len(self.threads) == cpus
            self.report["threads"] = self.threads
            self.sysregs = {}
            xml = ""
            offset = 0
            while True:
                answer = self.remote.command(f"qXfer:features:read:system-registers.xml:{offset:x},fff")
                if answer.startswith(("m", "l")):
                    xml += answer[1:]
                    offset += len(answer[1:].encode())
                    if answer.startswith("l"):
                        break
                else:
                    break
            if xml:
                (self.directory / "system-registers.xml").write_text(xml)
                number = 0
                for reg in ET.fromstring(xml).iter("reg"):
                    number = int(reg.get("regnum", str(number)))
                    self.sysregs[reg.attrib["name"]] = number
                    number += 1
            self.snapshot("initial native entry")
        except Exception:
            self.close()
            raise

    def snapshot(self, label, packet=None):
        event = {"event": label, "seconds": round(time.monotonic() - self.started, 4),
                 "stop_reply": packet, "cores": []}
        if self.debugger_ledgers:
            event["host_start_monotonic_ns"] = time.monotonic_ns()
        for thread in self.threads:
            self.remote.command("Hg" + thread)
            regs = self.remote.registers()
            pc = int(regs["r15"], 16)
            info = {"thread": thread, "registers": regs}
            system = {}
            wanted = ("MPIDR", "TTBR0", "TTBR1", "TTBCR", "SCTLR", "VBAR", "CBAR", "DACR", "CNTFRQ", "SCR", "IFSR", "DFSR", "DFAR", "IFAR", "SPSR")
            for name, number in self.sysregs.items():
                if name.startswith(wanted):
                    raw = self.remote.command(f"p{number:x}")
                    if raw and not raw.startswith("E") and not set(raw) <= {"x"}:
                        system[name] = hex(int.from_bytes(bytes.fromhex(raw), "little"))
            info["system_registers"] = system
            offset = pc - 0x10020000
            if 0 <= offset <= len(self.blob) - 16:
                expected = self.blob[offset:offset+16]
                actual = self.remote.memory(pc, 16)
                info.update(instruction_bytes=actual.hex(), original_bytes=expected.hex(),
                            original_instructions_verified=(actual == expected))
            info["mailbox_04008ffc"] = self.remote.memory(0x04008ffc, 4).hex()
            event["cores"].append(info)
        event["query_cpus_fast"] = self.monitor.command("query-cpus-fast")
        if self.debugger_ledgers:
            event["host_end_monotonic_ns"] = time.monotonic_ns()
        self.report["events"].append(event)
        print(json.dumps({"event": label, "cores": [{"thread": c["thread"],
                                                       "pc": c["registers"]["r15"],
                                                       "sp": c["registers"]["r13"]}
                                                      for c in event["cores"]]}, ensure_ascii=False), flush=True)
        if packet and "thread:" in packet:
            self.remote.command("Hg" + packet.split("thread:")[1].split(";")[0])
        return event

    def run_to(self, address, label, thumb=False, observers=None):
        assert not self.running
        observers = observers or {}
        if address in observers:
            raise ValueError("Checkpoint overlaps a passive observation point")
        print(f"{self.role}: run to {address:08x} ({label})", flush=True)
        width = 2 if thumb else 4
        assert self.remote.command(f"Z1,{address:x},{width}") == "OK"
        for pc in observers:
            expected = self.blob[pc - 0x10020000:pc - 0x10020000 + 16]
            assert len(expected) == 16 and self.remote.memory(pc, 16) == expected, hex(pc)
            assert self.remote.command(f"Z1,{pc:x},2") == "OK"
        hits = 0
        while True:
            self.remote.send("c")
            self.running = True
            try:
                packet = self.remote.receive()
            except socket.timeout:
                self.remote.sock.sendall(b"\x03")
                packet = self.remote.receive()
                self.running = False
                self.snapshot("bounded execution timeout", packet)
                raise RuntimeError(f"Did not reach {address:08x} within 15 seconds")
            self.running = False
            if "thread:" not in packet:
                raise RuntimeError("QEMU exited before checkpoint: " + packet)
            thread = packet.split("thread:")[1].split(";")[0]
            self.remote.command("Hg" + thread)
            regs = self.remote.registers()
            pc = int(regs["r15"], 16)
            if pc not in observers:
                break
            observers[pc](self.remote, regs)
            hits += 1
            if hits > 256:
                raise RuntimeError("Passive checkpoint observations exceeded the 256-hit bound")
            assert self.remote.command(f"z1,{pc:x},2") == "OK"
            assert self.remote.command("Hc" + thread) == "OK"
            self.remote.send("s")
            step = self.remote.receive()
            assert step.startswith("T05"), step
            assert self.remote.command("Hc-1") == "OK"
            assert self.remote.command(f"Z1,{pc:x},2") == "OK"
        if pc != address:
            self.snapshot("unexpected stop", packet)
            raise RuntimeError(f"Unexpected PC {pc:08x}; expected {address:08x}")
        assert self.remote.command(f"z1,{address:x},{width}") == "OK"
        for pc in observers:
            assert self.remote.command(f"z1,{pc:x},2") == "OK"
        return self.snapshot(label, packet)

    def boot_task(self, after_hardware=True):
        """Follow native startup to a safe task checkpoint, with no RAM fixture."""
        for address, label in [(0x1002bd2c, "MMU enabled; native MPIDR dispatch"),
                               (0x1002bdb8, "core 0 early startup"),
                               (0x1002be50, "before original DDR entry"),
                               (0x1002be64, "DDR entry returned"),
                               (0x1002bf98, "native data copies and DMA fill completed"),
                               (0x104393a4 if self.role == "master" else 0x10167090,
                                "C runtime ARM trampoline"),
                               (0x10103c18 if self.role == "master" else 0x100356c8,
                                "native RTOS entry")]:
            self.run_to(address, label)
        self.report["rtos_entry_reached"] = True
        rtos = 0x10103c18 if self.role == "master" else 0x100356c8
        for address, label in [(rtos + 0xc8, "RTOS shared initialization flag set"),
                               (rtos + 0x40, "RTOS per-core startup"),
                               (0x10200034 if self.role == "master" else 0x10052f74,
                                "native boot task body; RTOS scheduler active")]:
            event = self.run_to(address, label,
                                thumb=address in (0x10200034, 0x10052f74))
        self.report["boot_task_reached"] = True
        if after_hardware:
            event = self.run_to(0x10200042 if self.role == "master" else 0x10052f7e,
                                "boot task after hardware setup", thumb=True)
            self.report["hardware_setup_reached"] = True
        return event

    def close(self):
        for h in (self.remote, self.monitor):
            if h:
                try:
                    h.sock.close() if isinstance(h, Remote) else h.close()
                except OSError:
                    pass
        if self.process and self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                self.process.kill(); self.process.wait()
        self.log.close()
        self.report["log_retention"] = self.log.summary()
        self.report["exit_code"] = self.process.returncode if self.process else None
        self.report["QEMU_process_lifecycle"] = self.process_ledger.closed(self.process)
        self.report["seconds"] = round(time.monotonic() - self.started, 4)
        if self.debugger_ledgers:
            for ledger in self.debugger_ledgers.values():
                ledger.finish()
            self.report["debugger_API_byte_ledgers"] = {
                name: ledger.summary() for name, ledger in self.debugger_ledgers.items()}
        trace = self.report.get("source50_TCG_trace_path")
        if trace:
            path = Path(trace)
            self.report["source50_TCG_trace_retained"] = path.exists()
            if path.exists():
                body = path.read_bytes()
                self.report["source50_TCG_trace_identity"] = dict(path=str(path), bytes=len(body),
                    sha256=hashlib.sha256(body).hexdigest())
        trace = self.report.get("boot_TCG_trace_path")
        if trace:
            path = Path(trace)
            self.report["boot_TCG_trace_retained"] = path.exists()
            if path.exists():
                body = path.read_bytes()
                self.report["boot_TCG_trace_identity"] = dict(path=str(path), bytes=len(body),
                    sha256=hashlib.sha256(body).hexdigest())
        log = (self.directory / "qemu.log").read_text(errors="replace")
        self.report["first_unmodeled"] = next((x for x in log.splitlines() if x.startswith("Z6II_UNMODELED")), None)
        # error_report may prepend the executable name. Preserve the actual
        # wire stop separately from the legacy strict-MMIO classification.
        self.report["native_wire_boundary_lines"] = [
            x for x in log.splitlines() if "Z6II_MCU_WIRE_" in x and "BOUNDARY" in x]
        self.report["first_native_wire_boundary"] = next(
            iter(self.report["native_wire_boundary_lines"]), None)
        self.report["first_hardware_boundary"] = next((
            x for x in log.splitlines() if x.startswith("Z6II_UNMODELED") or
            ("Z6II_MCU_WIRE_" in x and "BOUNDARY" in x)), None)
        self.report["native_wire_ACK_write_lines"] = [
            x for x in log.splitlines() if "Z6II_MCU_WIRE_MASTER_ACK " in x]
        self.report["native_wire_known_wait_lines"] = [
            x for x in log.splitlines() if "Z6II_MCU_WIRE_KNOWN_WAIT_" in x]
        self.report["cpu_states_on_unmodeled"] = [x for x in log.splitlines() if x.startswith(("Z6II_CPU", "Z6II_REG"))]
        (self.directory / "结果.json").write_text(json.dumps(self.report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps({"output": str(self.directory), "first_unmodeled": self.report["first_unmodeled"],
                          "first_hardware_boundary": self.report["first_hardware_boundary"],
                          "error": self.report.get("error")}, ensure_ascii=False), flush=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--role", choices=["master", "slave"], default="master")
    parser.add_argument("--label", default="startup")
    parser.add_argument("--cpus", type=int, choices=[1, 2], default=2)
    parser.add_argument("--assisted", action="store_true")
    parser.add_argument("--link-test-peer", action="store_true")
    parser.add_argument("--to", type=lambda s: int(s, 0))
    args = parser.parse_args()
    p = Probe(args.role, args.label, args.cpus, assisted=args.assisted,
              link_test_peer=args.link_test_peer)
    try:
        p.boot_task()
        address = args.to or (0x1038a210 if args.role == "master" else 0x10060cc8)
        p.run_to(address, "requested native checkpoint" if args.to else
                 "native dual-engine queue initialization", thumb=True)
        p.report["requested_checkpoint_reached" if args.to else "dual_init_reached"] = True
    except Exception as e:
        p.report["error"] = str(e)
        p.report["traceback"] = traceback.format_exc()
    finally:
        p.close()


if __name__ == "__main__":
    main()
