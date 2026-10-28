"""Run the strict EX1850 reset board with read-only initial verification.

QEMU resets Cortex-M from the original flash vector. Default runs use no
guest calls, RAM/register fixtures, or replay packets. An explicitly selected
auxiliary-power spec permits one source-bound configuration byte, reported
separately from diagnostic replay. Hardware breakpoints preserve instructions.
Unknown device access terminates this owned process before returning a value.
"""
import argparse
import hashlib
import json
import os
import re
import select
import shutil
import subprocess
import sys
import time
import traceback
from meaningful_qemu_log import MeaningfulQemuLog
from pathlib import Path

from host_env import ROOT, WORK, environment
from firmware_constants import BASE, RAM, RAM_SIZE, INPUT, EXPECTED_SHA
from run_evidence import ProcessLedger

sys.path.insert(0, str(WORK / "tools"))
from interactive import QMP, free_port
from rsp import Remote
from debugger_byte_ledger import ByteLedger, audited_remote, audited_qmp
AuditedRemote = audited_remote(Remote)
AuditedQMP = audited_qmp(QMP)


def write_host_input_state(path, value):
    """Publish only the latest small acknowledgement for an external controller."""
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False) + "\n")
    temporary.replace(path)


def collect_native_log(path, sample_limit=2048):
    """Read retained event samples; distinguish them from emitted input counts."""
    from collections import Counter, deque
    started = time.monotonic()
    exact_routes = {'EX1850_MCU_WIRE_BOUNDARY': ['native_wire_boundary_lines'], 'EX1850_RCC_APB1ENR': ['modeled_RCC_accesses'], 'EX1850_PWR_CR': ['modeled_PWR_control_accesses'], 'EX1850_RCC_CR': ['modeled_clock_and_FLASH_access_samples'], 'EX1850_RCC_PLLCFGR': ['modeled_clock_and_FLASH_access_samples'], 'EX1850_RCC_CFGR': ['modeled_clock_and_FLASH_access_samples'], 'EX1850_RCC_AHB1ENR': ['modeled_clock_and_FLASH_access_samples'], 'EX1850_RCC_AHB2ENR': ['modeled_clock_and_FLASH_access_samples'], 'EX1850_RCC_APB2ENR': ['modeled_clock_and_FLASH_access_samples'], 'EX1850_RCC_BDCR': ['modeled_clock_and_FLASH_access_samples'], 'EX1850_FLASH_ACR': ['modeled_clock_and_FLASH_access_samples'], 'EX1850_BOUNDARY_FLASH': ['FLASH_controller_events'], 'EX1850_CLOCK_EVENT': ['clock_state_transition_events'], 'EX1850_HCLK': ['clock_state_transition_events'], 'EX1850_TIMER_CLOCK_SYNC': ['TIM5_TIM11_old_rate_synchronization_events'], 'EX1850_NATIVE_DEEP_SLEEP_REQUEST': ['original_deep_sleep_request_boundary_events'], 'EX1850_ICOUNT_IDLE_STOP': ['host_debug_clock_idle_and_warp_audit'], 'EX1850_ICOUNT_WARP': ['host_debug_clock_idle_and_warp_audit'], 'EX1850_TIM5_R': ['TIM5_native_access_samples'], 'EX1850_TIM5_W': ['TIM5_native_access_samples'], 'EX1850_TIM5_EVENT': ['TIM5_native_access_samples'], 'EX1850_TIM11_R': ['TIM11_native_access_samples'], 'EX1850_TIM11_W': ['TIM11_native_access_samples'], 'EX1850_TIM11_EVENT': ['TIM11_native_access_samples'], 'EX1850_TIM12_R': ['TIM12_native_access_samples'], 'EX1850_TIM12_W': ['TIM12_native_access_samples'], 'EX1850_TIM12_EVENT': ['TIM12_native_access_samples'], 'EX1850_TIM12_RESET': ['TIM12_native_access_samples'], 'EX1850_TIM8_IDLE': ['TIM8_shared_IRQ43_reset_idle_accesses'], 'EX1850_TIM1_IDLE': ['TIM1_shared_IRQ_reset_idle_accesses'], 'EX1850_GPIO_CONTROL': ['GPIO_control_accesses'], 'EX1850_GPIO_PIN_PROFILE': ['GPIO_declared_static_pin_profiles_and_original_IDR_reads'], 'EX1850_GPIO_INPUT': ['GPIO_declared_static_pin_profiles_and_original_IDR_reads'], 'EX1850_SYSCFG_CONTROL': ['SYSCFG_EXTICR_control_accesses'], 'EX1850_EXTI_CLEAR': ['EXTI_pending_and_edge_clear_accesses'], 'EX1850_EXTI_CONTROL': ['EXTI_pending_and_edge_clear_accesses'], 'EX1850_APB1_SPI_RESET': ['APB1_SPI_disabled_control_events'], 'EX1850_APB1_SPI_BOUNDARY': ['APB1_SPI_strict_boundary_events'], 'EX1850_RCC_APB1RSTR': ['APB1RSTR_control_and_I2C_reset_events'], 'EX1850_I2C_RESET': ['APB1RSTR_control_and_I2C_reset_events'], 'EX1850_RTC_WPR': ['RTC_write_protection_accesses'], 'EX1850_RTC_BACKUP_RESET': ['RTC_write_protection_accesses'], 'EX1850_RTC_ISR': ['RTC_status_and_clock_events'], 'EX1850_RTC_CLOCK_EVENT': ['RTC_status_and_clock_events'], 'EX1850_RTC_CONTROL': ['RTC_status_and_clock_events'], 'EX1850_RTC_CALENDAR': ['RTC_status_and_clock_events'], 'EX1850_RTC_BACKUP': ['RTC_status_and_clock_events'], 'EX1850_RTC_ALARM_EVENT': ['RTC_status_and_clock_events', 'RTC_alarm_control_and_completion_events'], 'EX1850_RTC_ALARM_CONTROL': ['RTC_status_and_clock_events', 'RTC_alarm_control_and_completion_events'], 'EX1850_RTC_EXTI17_EDGE': ['RTC_status_and_clock_events', 'RTC_EXTI17_and_IRQ41_events'], 'EX1850_RTC_IRQ41': ['RTC_status_and_clock_events', 'RTC_EXTI17_and_IRQ41_events'], 'EX1850_I2C_CONTROL': ['I2C_controller_configuration_accesses'], 'EX1850_I2C2_CONTROL': ['I2C2_controller_configuration_accesses'], 'EX1850_DMA1_CONTROL': ['DMA1_configuration_status_and_flag_clear_accesses'], 'EX1850_DMA1_STATUS': ['DMA1_configuration_status_and_flag_clear_accesses'], 'EX1850_DMA1_FLAG_CLEAR': ['DMA1_configuration_status_and_flag_clear_accesses'], 'EX1850_ADC_CONTROL': ['ADC1_native_configuration_and_conversion_boundary'], 'EX1850_ADC_CONVERSION_BOUNDARY': ['ADC1_native_configuration_and_conversion_boundary'], 'EX1850_ADC_START': ['ADC1_native_configuration_and_conversion_boundary'], 'EX1850_ADC_CONVERSION_EVENT': ['ADC1_native_configuration_and_conversion_boundary'], 'EX1850_ADC_IRQ18': ['ADC1_native_configuration_and_conversion_boundary'], 'EX1850_ADC_PIN_PROFILE': ['ADC1_native_configuration_and_conversion_boundary'], 'EX1850_I2C_STATUS': ['I2C_bus_status_and_clocked_events'], 'EX1850_I2C_EVENT': ['I2C_bus_status_and_clocked_events'], 'EX1850_I2C_ADDRESS': ['I2C_bus_status_and_clocked_events'], 'EX1850_I2C_POINTER': ['I2C_bus_status_and_clocked_events'], 'EX1850_EXTERNAL_INPUT_BOUNDARY': ['external_device_input_boundary_events'], 'EX1850_UNMODELED_DEVICE_EVENT': ['external_device_input_boundary_events'], 'EX1850_I2C_RECEIVE_EVENT': ['I2C_received_byte_events_and_original_DR_reads', 'MAX77711_clocked_readback_events'], 'EX1850_I2C_RECEIVE_DR': ['I2C_received_byte_events_and_original_DR_reads'], 'EX1850_I2C_TRANSMIT_DR': ['I2C_transmit_slots_and_PCAL_register_writes'], 'EX1850_I2C_TRANSMIT_EVENT': ['I2C_transmit_slots_and_PCAL_register_writes'], 'EX1850_PCAL_REGISTER': ['I2C_transmit_slots_and_PCAL_register_writes'], 'EX1850_MAX77711_REGISTER': ['MAX77711_original_written_register_events'], 'EX1850_EXTERNAL_PIN_PROFILE': ['explicit_external_pin_profile_lines'], 'EX1850_BOUNDARY': ['boundary_hardware_state_lines'], 'EX1850_BOUNDARY_CPU': ['boundary_CPU_register_observation_lines']}
    prefix_routes = {'EX1850_FLASH_': ['FLASH_controller_events'], 'EX1850_SPI2_': ['SPI2_DMA1_events'], 'EX1850_DMA1_': ['SPI2_DMA1_events'], 'EX1850_APB1_SPI_CONTROL_': ['APB1_SPI_disabled_control_events']}
    keys = ['native_wire_boundary_lines', 'modeled_RCC_accesses', 'modeled_PWR_control_accesses', 'modeled_clock_and_FLASH_access_samples', 'FLASH_controller_events', 'clock_state_transition_events', 'TIM5_TIM11_old_rate_synchronization_events', 'original_deep_sleep_request_boundary_events', 'host_debug_clock_idle_and_warp_audit', 'TIM5_native_access_samples', 'TIM11_native_access_samples', 'TIM12_native_access_samples', 'TIM8_shared_IRQ43_reset_idle_accesses', 'TIM1_shared_IRQ_reset_idle_accesses', 'GPIO_control_accesses', 'GPIO_declared_static_pin_profiles_and_original_IDR_reads', 'SYSCFG_EXTICR_control_accesses', 'EXTI_pending_and_edge_clear_accesses', 'SPI2_DMA1_events', 'APB1_SPI_disabled_control_events', 'APB1_SPI_strict_boundary_events', 'APB1RSTR_control_and_I2C_reset_events', 'RTC_write_protection_accesses', 'RTC_status_and_clock_events', 'RTC_alarm_control_and_completion_events', 'RTC_EXTI17_and_IRQ41_events', 'I2C_controller_configuration_accesses', 'I2C2_controller_configuration_accesses', 'DMA1_configuration_status_and_flag_clear_accesses', 'ADC1_native_configuration_and_conversion_boundary', 'I2C_bus_status_and_clocked_events', 'external_device_input_boundary_events', 'I2C_received_byte_events_and_original_DR_reads', 'I2C_transmit_slots_and_PCAL_register_writes', 'MAX77711_original_written_register_events', 'MAX77711_clocked_readback_events', 'explicit_external_pin_profile_lines', 'boundary_hardware_state_lines', 'boundary_CPU_register_observation_lines', 'original_NVIC_reset_write_and_shutdown_trace']
    counts = Counter()
    token_counts = Counter()
    head = {key: [] for key in keys}
    tail = {key: deque(maxlen=sample_limit // 2) for key in keys}
    first_boundary = None
    unmodeled, device_events = [], []
    received_total = 0
    line_count = 0
    unmodeled_re = re.compile(r"EX1850_UNMODELED ([RW]) addr=([0-9a-f]+) size=(\d+) value=([0-9a-f]+) pc=([0-9a-f]+)")
    device_re = re.compile(r"EX1850_UNMODELED_DEVICE_EVENT event=I2C_receive_input device=(\S+) address7=([0-9a-f]+) reg=([0-9a-f]+) CPU_MMIO_instruction_executed=0")
    with path.open() as stream:
        for raw in stream:
            line_count += 1
            line = raw.rstrip('\r\n')
            token = line.partition(' ')[0]
            token_counts[token] += 1
            selected = list(exact_routes.get(token, ()))
            for prefix, names in prefix_routes.items():
                if token.startswith(prefix):
                    selected.extend(names)
            if (("nvic_sysreg_write" in line and "addr 0xd0c" in line) or
                    "qemu_system_shutdown_request" in line):
                selected.append("original_NVIC_reset_write_and_shutdown_trace")
            for key in selected:
                if key == "MAX77711_clocked_readback_events" and "address7=4f " not in line:
                    continue
                counts[key] += 1
                if len(head[key]) < sample_limit // 2:
                    head[key].append(line)
                else:
                    tail[key].append(line)
            if first_boundary is None and ("EX1850_UNMODELED" in line or "EX1850_MCU_WIRE_BOUNDARY" in line):
                first_boundary = line
            if token.startswith("EX1850_UNMODELED"):
                unmodeled.extend(unmodeled_re.findall(line))
                device_events.extend(device_re.findall(line))
            if token == "EX1850_I2C_RECEIVE_EVENT":
                m = re.search(r"total_received=(\d+)", line)
                if m:
                    received_total = int(m[1])
    events = {key: head[key] + list(tail[key]) for key in keys}
    retention_path = path.with_name(path.stem + "-retention.json")
    retention = json.loads(retention_path.read_text()) if retention_path.exists() else None
    return events, dict(schema="ex1850-streamed-log-summary/2", raw_log=str(path),
        raw_log_bytes=path.stat().st_size, lines=line_count, complete_counts=dict(counts),
        counts_scope="retained_log_only" if retention else "full_emitted_log",
        complete_raw_log_retained=not bool(retention), log_retention=retention,
        sample_limit_per_category=sample_limit, sample_policy="first half and last half of retained events",
        truncated_categories=[key for key in keys if counts[key] > sample_limit],
        elapsed_seconds=round(time.monotonic() - started, 3)), dict(
        first_boundary=first_boundary, unmodeled=unmodeled, device_events=device_events,
        received_total=received_total, flash_counts={name:token_counts['EX1850_FLASH_'+name]
            for name in ('PROFILE','RESET','ACCEPT','COMPLETE','ARRAY_W','REG_R','REG_W','IRQ','BUS_ERROR','BOUNDARY','STALL','RESUME')})


POINTS = {
    0x08003804: "original C scatter initializer from reset",
    0x08020084: "original application entry from reset",
    0x080211D0: "original MCU main module initializer",
    0x0804219C: "original TIM5 coordinator initializer",
    0x080498F8: "original TIM5 base configuration",
    0x08045AE6: "original TIM5 start internal upcounter",
    0x08000650: "original HAL tick increment via native interrupt path",
    0x08045000: "original RTC initialization from native module coordinator",
    0x080394F0: "original cold RTC reset after missing retained state",
    0x08000598: "original RTC cold-init LSE stability wait",
    0x080491D8: "original RTC hardware initialization-mode entry",
    0x080453F4: "original RTC shadow synchronization",
    0x08039982: "original RTC check completion before actual callback",
    0x0803A1E0: "original SYS receiver of RTC completion",
    0x0802140C: "original coordinator callback from SYS readiness",
    0x080212E8: "original coordinator wait for RTC/SYS mask2",
    0x080212EC: "original coordinator returned from RTC/SYS mask2 wait",
    0x080005E8: "original LSE timeout branch after more than 5000 HAL ticks",
    0x08000612: "original AIRCR SYSRESETREQ instruction after RTC/LSE timeout",
    0x08043E3C: "original I2C hardware controller initialization",
    0x08044648: "original I2C1 asynchronous memory-read request",
    0x0802FCE0: "original I2C1 event IRQ wrapper",
    0x08046FF0: "original I2C1 first address44 DR write instruction",
    0x08047042: "original I2C1 memory pointer transmit handler",
    0x080470A2: "original I2C1 memory-read repeated START branch",
    0x0802FCBC: "original I2C1 error IRQ wrapper",
    0x0802FCD6: "original I2C1 error wrapper publishes flag2",
    0x0804469A: "original I2C1 BUSY countdown exhaustion returns1",
    0x0802FE9E: "original I2C1 first read wrapper return",
    0x08030098: "original IO expander caller ignores first read result",
    0x0803016A: "original IO expander all-register setup return",
    0x080306F8: "original IO expander cached asynchronous input update",
    0x08038058: "original KEY consumes six-byte pins and configuration mask packet",
    0x08037CC8: "original KEY input snapshot and completion producer entry",
    0x08037EA8: "original KEY completion callback load",
    0x08021418: "original coordinator KEY completion event consumer",
    0x080437D4: "original GPIO deinitialize with SYSCFG EXTICR cleanup",
    0x08043AE8: "original I2C1 deinitialization after IO expander setup",
    0x08043B14: "original I2C1 deinitialization returned0 after actual pin cleanup",
    0x08044B56: "original I2C2 MSP initialization before APB1RSTR bit22 assert/release",
    0x08044B6A: "original I2C MSP initialization before critical section exit",
    0x08043688: "original DMA stream initialization from actual caller",
    0x08043754: "original DMA stream initializer returned0 after configuration and flag clear",
    0x08038C20: "original key initializer snapshots and clears EXTI pending/edge state",
    0x08038C52: "original key EXTI clear routine return after actual PR W1C and edge clears",
    0x08043AC8: "original GPIO pin-read entry before any external input value is supplied",
    0x0802A6AA: "original module02 stores PC5 inverted predicate return",
    0x0802A830: "original module02 prepares status callback after its input dependencies",
    0x0802A83E: "original module02 tail-dispatches its actual status payload",
    0x080383F4: "original KEY receiver consumes module02 status payload",
    0x08038258: "original KEY worker dispatches its actual event mask",
    0x080377A4: "original KEY event4 prepares module02 status request",
    0x08037A5A: "original KEY worker calls the native STOP preparation chain",
    0x08039270: "original native low-power clock and pin preparation entry",
    0x08044BDA: "original PWR FPDS bit9 bitband write instruction",
    0x08044BF8: "original PWR LPDS selection write instruction",
    0x08044C02: "original SLEEPDEEP SCR write before unmodeled STOP request",
    0x0802B87C: "original second module02 GPIO predicate entry",
    0x08023218: "original module02 three-sample averaging entry",
    0x0802338C: "original ADC descriptor acquisition and channel setup entry",
    0x080430CA: "original ADC HAL initialization entry",
    0x08042F3C: "original ADC channel configuration entry",
    0x08038FB0: "original registered TIM11 IRQ callback signals its RTOS worker",
    0x08038FB4: "original TIM11 callback requests its actual flag1 before tail call",
    0x08039330: "original TIM11 service initializer and IRQ callback registration",
    0x08039390: "original TIM11 service initializer returns actual success after registration and start",
    0x08021372: "original coordinator next mask1 wait",
    0x080213A2: "original coordinator ordinary module phase1 dispatch",
    0x0802EA60: "original configuration phase dispatcher",
    0x0802F84C: "original configuration first-phase continuation",
    0x080387E4: "original MAX candidate write/three-readback routine entry",
    0x08038880: "original readback comparison accepted all three samples",
    0x08038890: "original write/readback routine return after actual comparison",
    0x0803CC8C: "original ADC interrupt conversion request entry (0803CC8C -> HAL_ADC_Start_IT)",
    0x0803CD20: "original ADC worker event wait entry before 4 IRQ18 conversions",
    0x0803CDF8: "original registered ADC IRQ18 callback entry (0803CDF8)",
    0x0803CD56: "original ADC worker post-4-conversion average and HAL_ADC_DeInit completion",
    0x0803E2C4: "original 0803E2C0 return after 0803CC8C before 0803E2AC selector classification",
    0x0803E350: "original 0803E2C0 completion before 0803E128 notification",
    0x0803E518: "original 0803E094 second subhandler 0803E518 entry",
    0x0803E0C4: "original 0803E094 event loop completion return",
    0x080214FC: "original caller 080214E8 post-0803E094 return",
}

# One-shot passive sites for the native CAPCOM tag1 producer. They are
# inactive unless ROM observation is explicitly selected by the caller.
CAPCOM_STATUS_POINTS = {
    0x08036868: "original CAPCOM receiver of event03020001/03020002",
    0x08036B70: "original CAPCOM tag1 producer entry",
    0x08036B84: "original CAPCOM property36 read returned",
    0x08036BA8: "original CAPCOM tag1 byte4 store before execution",
    0x08036BCE: "original CAPCOM tag1 descriptor send call",
}
POINTS.update(CAPCOM_STATUS_POINTS)


# Record the original HAL request before any address byte or external reply.
# The historical one-shot memory-read point captured only PCAL initialization;
# later BatCmFg2/Fg3 requests require bounded repeated observations.
I2C_REQUEST_POINTS = {
    0x08044138: "original HAL I2C asynchronous master receive request",
    0x08044200: "original HAL I2C asynchronous master transmit request",
    0x08044648: "original HAL I2C asynchronous memory-read request",
    0x080449B0: "original HAL I2C asynchronous memory-write request",
}

# These unchanged instructions were checked against the original image.
# 08032120 receives the queued four-word descriptor in r0; 0802ee54
# receives the native completion result; 0802ee60 dispatches flag0x1000
# after storing that result. These observers never supply a result or flag.
FLASH_REQUEST_POINTS = {
    0x08032120: "original queued Flash-save descriptor entry",
    0x0802EE54: "original MODE-save completion callback entry",
    0x0802EE60: "original MODE callback dispatch after storing the result",
}


# Original RTC alarm IRQ, deferred worker and calendar publication chain.
# SRAM and registers are observed only. No peripheral reads are made by GDB.
# 080201FC is the common vector wrapper for many external IRQs. Trapping it
# throughout cold boot stopped on unrelated I2C IRQ31, before RTC registered.
# Observe the RTC-specific dispatch and callback with actual IPSR57 instead;
# their read-only context still contains the relocated vector and both slots.
RTC_ALARM_POINTS = {
    0x08041134: "original RTC IRQ41 registered dispatch stub",
    0x080398F8: "original RTC IRQ callback publishes worker event400",
    0x08039964: "original RTC worker event-mask entry",
    0x08039AFA: "original RTC worker before native alarm service",
    0x08039430: "original alarm service entry",
    0x0803943E: "original EXTI17 PR W1C instruction",
    0x08039440: "original EXTI17 PR W1C instruction completed",
    0x0803945C: "original RTC ALRAF ISR W0C instruction",
    0x0803945E: "original RTC ALRAF ISR W0C requested",
    0x08039468: "original native ALRAF callback BLX r2 instruction",
    0x08039918: "original RTC calendar notification callback",
    0x080394B4: "original calendar GetTime returned into SRAM frame",
    0x080394BE: "original calendar GetDate returned into SRAM frame",
    0x080394E2: "original calendar caller six output stores completed",
    0x0803A284: "original SYS event4202000a calendar callback entry",
    0x0803A2A4: "original SYS six-byte calendar stores completed",
    0x0803A2AA: "original SYS calendar event80000 dispatch",
    0x08039B00: "original RTC worker clears native NVIC pending",
    0x08039B04: "original RTC worker native NVIC pending-clear returned",
    0x08039B0A: "original RTC worker tail-reenables native IRQ41",
}


def gpio_pin_levels(value):
    match = re.fullmatch(r"([A-Ha-h])=(0[xX][0-9a-fA-F]+|[0-9]+)", value)
    if not match:
        raise argparse.ArgumentTypeError("use a port and explicit 16-bit level, for example C=0xffff")
    levels = int(match[2], 0)
    if not 0 <= levels <= 0xffff:
        raise argparse.ArgumentTypeError("GPIO pin levels must fit in 16 bits")
    return match[1].upper(), levels


def adc_channel_mv(value):
    match = re.fullmatch(r"([0-9]+)=(0[xX][0-9a-fA-F]+|[0-9]+)", value)
    if not match:
        raise argparse.ArgumentTypeError("use an external ADC channel and millivolts, for example 1=1800")
    channel, mv = int(match[1]), int(match[2], 0)
    if not 0 <= channel <= 15 or not 0 <= mv <= 5000:
        raise argparse.ArgumentTypeError("ADC external channel must be0..15 and millivolts0..5000")
    return channel, mv


def pcal_pin_event(value):
    match = re.fullmatch(r"(0[xX][0-9a-fA-F]+|[0-9]+):(0[xX][0-9a-fA-F]+|[0-9]+):(0[xX][0-9a-fA-F]+|[0-9]+)", value)
    if not match:
        raise argparse.ArgumentTypeError("use MCU virtual ns:24-bit mask:masked levels")
    when, mask, levels = (int(part, 0) for part in match.groups())
    if not 0 < when < 2**63 or not 0 < mask <= 0xffffff or not 0 <= levels <= 0xffffff or levels & ~mask:
        raise argparse.ArgumentTypeError("event needs positive time and mask, with levels inside the mask")
    return when, mask, levels


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--observe", action="store_true")
    parser.add_argument("--auxiliary-power-spec", type=Path,
                        help="Explicit one-shot synthetic external-power config at the original caller; separate from diagnostic RAM replay")
    parser.add_argument("--observe-address", type=lambda value: int(value, 0),
                        action="append", default=[],
                        help="Select only these passive ROM breakpoints instead of defaults; repeat per address")
    parser.add_argument("--i2c-request-trace", action="store_true",
                        help="Read-only HAL request descriptors, at most32 hits per original entry; no requests or responses injected")
    parser.add_argument("--battery-config-trace", action="store_true",
                        help="Passive original group4 conversion and 72-byte copy timing; at most32 hits per ROM point")
    parser.add_argument("--battery-task-trace", action="store_true",
                        help="Passive battery refresh entries/returns after the original nonzero config copy; at most32 hits per ROM point")
    parser.add_argument("--label", default="strict-reset")
    parser.add_argument("--output-dir", type=Path,
                        help="New directory for this run; must not already exist")
    parser.add_argument("--manifest", type=Path, default=WORK / "exmcu/build-manifest.json",
                        help="Version-locked build manifest including its matching board source")
    parser.add_argument("--seconds", type=float, default=5)
    parser.add_argument("--usart1-negative-peer", choices=("zero-response", "partial-timeout"),
                        help="Explicit synthetic serial authentication negative; only public UART TX is read, never MCU RAM/RNG")
    parser.add_argument("--usart1-battery-spec", type=Path,
                        help="Source-bound battery wire replies matched to explicit public external RNG words; no guest-state access")
    parser.add_argument("--rng-public-word", type=lambda value: int(value, 0), action="append", default=[],
                        help="Explicit synthetic external nonzero RNG DR word; repeat up to64; exhaustion is a strict boundary")
    parser.add_argument("--usart1-peer-max-replies", type=int, default=3,
                        help="Bound serial replies: negative1..64; explicit battery1..8192")
    parser.add_argument("--initial-resource-startup-barrier", type=Path,
                        help="Run-local owner-only stopped gate during Master diagnostic RAM replay")
    parser.add_argument("--nvic-write-trace", choices=("on", "off"), default="off",
                        help="Optional bounded NVIC samples; default off retains shutdown and device events")
    parser.add_argument("--without-hse", action="store_true",
                        help="Absent external oscillator negative control; no HSE or PLL status success")
    parser.add_argument("--debug-clock-guard", choices=("on", "off"), default="on",
                        help="Prevent host debugger stops from being treated as guest WFI clock warp")
    parser.add_argument("--debug-warp-audit", action="store_true")
    parser.add_argument("--without-lse", action="store_true",
                        help="No low-speed crystal: original RTC failure path remains live")
    parser.add_argument("--i2c-bus", choices=("strict", "released", "sda-low"), default="strict",
                        help="Explicit unmeasured bus scenario; strict supplies no SR1/SR2 pad state")
    parser.add_argument("--i2c-slave", choices=("strict", "absent", "pcal6524"), default="strict",
                        help="Strict, absent-slave NACK, or explicit PCAL6524 address/pointer protocol hypothesis; input data remains unknown")
    parser.add_argument("--i2c-max77711", action="store_true",
                        help="Opt-in MAX77511/MAX77711 family at4F: VIO valid/PHCFG floating assumptions; only guest-written B2_CNFG_D23; OTP, rails, PGOOD and reset nets remain unknown")
    parser.add_argument("--i2c-absent-address", type=lambda value: int(value, 0),
                        action="append", default=[],
                        help="Explicit 7-bit absent device hypothesis; repeat per address. Other unmodeled addresses stop before ACK/NACK")
    parser.add_argument("--pcal-pin-levels", type=lambda value: int(value, 0),
                        help="Explicit 24-bit digital pin-level scenario, never a reset default or camera sample")
    parser.add_argument("--pcal-pin-event", type=pcal_pin_event, action="append", default=[],
                        help="Timed external input at MCU virtual ns:mask:levels; repeat in time order. Original firmware samples and serializes it")
    parser.add_argument("--pcal-host-input-file", type=Path,
                        help="Atomic host input commands (sequence, mask, levels); drives external PCAL pads through QMP, never MCU RAM or packets")
    parser.add_argument("--gpio-host-input-file", type=Path,
                        help="Atomic host commands (sequence, port, mask, levels); drives declared polled GPIO inputs through QMP, preserving original KEY processing")
    parser.add_argument("--gpio-pin-levels", type=gpio_pin_levels, action="append", default=[],
                        help="Explicit static driven inputs for one GPIO port, for example C=0xffff; repeat for another port")
    parser.add_argument("--gpio-masked-readpin", action="store_true",
                        help="At the unchanged original ReadPin only, discard unknown unused GPIO bits; selected AF pads and generic IDR reads stay strict")
    parser.add_argument("--gpio-pin-known-mask", type=gpio_pin_levels, action="append", default=[],
                        help="Limit known external input bits for a declared port; unspecified selected inputs still stop")
    parser.add_argument("--adc-channel-mv", type=adc_channel_mv, action="append", default=[],
                        help="Explicit external ADC node voltage; original pin analog mode and actual start remain required")
    parser.add_argument("--adc-vref-mv", type=int,
                        help="Explicit ADC reference millivolts, required with declared ADC node voltages")
    parser.add_argument("--flash-mode", choices=("strict", "functional"), default="strict",
                        help="Functional sector/x32 experiment requires every explicit voltage/protection/latency input")
    parser.add_argument("--flash-vdd-mv", type=int)
    parser.add_argument("--flash-nwrp", type=lambda value: int(value, 0),
                        help="Explicit active-low sector-protection option value0..0xfff; not a camera dump")
    parser.add_argument("--flash-erase-ns", type=int,
                        help="Positive virtual-time erase latency experiment input; not measured timing")
    parser.add_argument("--flash-program-ns", type=int,
                        help="Positive virtual-time x32 program latency experiment input; not measured timing")
    parser.add_argument("--flash-request-trace", action="store_true",
                        help="Read-only queued descriptor, full source, Flash and callback observations, at most32 hits per entry")
    parser.add_argument("--rtc-alarm-trace", action="store_true",
                        help="Passive original IRQ41, deferred service and calendar SRAM observations, at most32 hits per point")
    args = parser.parse_args()
    if not 1 <= args.usart1_peer_max_replies <= (8192 if args.usart1_battery_spec else 64):
        parser.error("USART1 reply budget exceeds the selected endpoint contract")
    if args.usart1_battery_spec and (args.usart1_negative_peer or args.auxiliary_power_spec):
        parser.error("Source-bound battery wire input is exclusive with serial negatives and auxiliary RAM inputs")
    if args.rng_public_word and (len(args.rng_public_word) > 64 or any(not 0 < word < 2**32 for word in args.rng_public_word)):
        parser.error("Public external RNG requires 1..64 nonzero u32 words")
    if args.usart1_battery_spec:
        from ex1850_battery_peer import load_spec
        battery_spec, _ = load_spec(args.usart1_battery_spec)
        if args.rng_public_word != battery_spec['public_entropy']['words']:
            parser.error("MCU RNG words must exactly match the battery peer public entropy specification")
    flash_inputs = {"VDD_mV": args.flash_vdd_mv, "nWRP": args.flash_nwrp,
                    "erase_ns": args.flash_erase_ns, "program_ns": args.flash_program_ns}
    if args.flash_mode == "functional":
        if any(value is None for value in flash_inputs.values()):
            parser.error("functional Flash requires VDD, nWRP, erase latency and program latency")
        if not 2700 <= args.flash_vdd_mv <= 3600 or not 0 <= args.flash_nwrp <= 0xfff:
            parser.error("Flash x32 experiment requires VDD2700..3600mV and nWRP0..0xfff")
        if any(not 0 < value <= 0x7fffffffffffffff
               for value in (args.flash_erase_ns, args.flash_program_ns)):
            parser.error("Flash latencies must be positive signed64-bit nanoseconds")
    elif any(value is not None for value in flash_inputs.values()):
        parser.error("Flash functional inputs require --flash-mode functional")
    if args.observe_address:
        if len(set(args.observe_address)) != len(args.observe_address) or any(
                address & 1 or not BASE <= address < BASE + 0x80000
                for address in args.observe_address):
            parser.error("passive breakpoints must be distinct halfword-aligned original ROM addresses")
        args.observe = True
        points = {address: POINTS.get(address, "caller-selected passive original ROM instruction")
                  for address in args.observe_address}
    else:
        points = dict(POINTS)
    if args.i2c_request_trace:
        args.observe = True
        points.update(I2C_REQUEST_POINTS)
    if args.battery_task_trace:
        from ex1850_battery_task import POINTS as BATTERY_TASK_POINTS, MAX_HITS as BATTERY_TASK_MAX_HITS
        args.battery_config_trace = True
    if args.battery_config_trace:
        from ex1850_battery_config import POINTS as BATTERY_CONFIG_POINTS, MAX_HITS as BATTERY_CONFIG_MAX_HITS
        args.observe = True
        points.update(BATTERY_CONFIG_POINTS)
    if args.flash_request_trace:
        args.observe = True
        points.update(FLASH_REQUEST_POINTS)
    if args.rtc_alarm_trace:
        args.observe = True
        points.update(RTC_ALARM_POINTS)
    if args.auxiliary_power_spec:
        from ex1850_auxiliary_power import POINTS as AUXILIARY_POWER_POINTS
        args.observe = True
        points.update(AUXILIARY_POWER_POINTS)
    observation_hits = {}
    if args.i2c_max77711 and (args.i2c_slave == "absent" or 0x4f in args.i2c_absent_address):
        parser.error("MAX77711 candidate4F cannot also be absent")
    if any(not 0 <= address <= 0x7f for address in args.i2c_absent_address):
        parser.error("I2C absent address must be 7-bit (0..0x7f)")
    if len(set(args.i2c_absent_address)) != len(args.i2c_absent_address):
        parser.error("declare each absent I2C address only once")
    if args.i2c_absent_address and args.i2c_slave == "absent":
        parser.error("global absent and per-address absent scenarios are exclusive")
    if args.i2c_slave == "pcal6524" and 0x22 in args.i2c_absent_address:
        parser.error("address 0x22 cannot be both the PCAL6524 candidate and absent")
    assert 0 < args.seconds <= 1200
    assert args.pcal_pin_levels is None or (args.i2c_slave == "pcal6524" and 0 <= args.pcal_pin_levels <= 0xffffff)
    if args.pcal_pin_event and (args.pcal_pin_levels is None or len(args.pcal_pin_event) > 64):
        parser.error("PCAL events require initial PCAL pin levels and at most64 events")
    if any(a[0] >= b[0] for a, b in zip(args.pcal_pin_event, args.pcal_pin_event[1:])):
        parser.error("PCAL event times must increase strictly")
    if args.pcal_host_input_file and (args.pcal_pin_levels is None or args.pcal_pin_event):
        parser.error("host PCAL input requires explicit initial levels and no virtual-time pin events")
    if args.pcal_host_input_file and args.pcal_host_input_file.exists():
        parser.error("host PCAL input file must be new for this run; stale commands cannot be replayed")
    gpio_levels = dict(args.gpio_pin_levels)
    if len(gpio_levels) != len(args.gpio_pin_levels):
        parser.error("declare each GPIO port only once")
    if args.gpio_host_input_file and not gpio_levels:
        parser.error("host GPIO input requires explicit initial GPIO levels")
    if args.gpio_host_input_file and args.gpio_host_input_file.exists():
        parser.error("host GPIO input file must be new for this run; stale commands cannot be replayed")
    gpio_known = dict(args.gpio_pin_known_mask)
    if len(gpio_known) != len(args.gpio_pin_known_mask) or not set(gpio_known) <= set(gpio_levels):
        parser.error("GPIO known masks require distinct ports with declared input levels")
    adc_levels = dict(args.adc_channel_mv)
    if len(adc_levels) != len(args.adc_channel_mv):
        parser.error("declare each ADC channel only once")
    if adc_levels:
        if args.adc_vref_mv is None or not 1 <= args.adc_vref_mv <= 5000:
            parser.error("declare ADC VREF in1..5000 millivolts with ADC node voltages")
        if any(value > args.adc_vref_mv for value in adc_levels.values()):
            parser.error("ADC node voltage must lie between0 and the declared VREF")
    elif args.adc_vref_mv is not None:
        parser.error("ADC VREF alone does not declare external node voltages")
    directory = args.output_dir.resolve() if args.output_dir else (
        ROOT / "outputs/Z6II双EXPEED6分析/QEMU运行/EXMCU探针" / (
        time.strftime("%Y%m%d-%H%M%S") + "-QEMU-original-reset-" + args.label))
    directory.mkdir(parents=True, exist_ok=False)
    process_ledger = ProcessLedger(directory, "MCU")
    manifest_path = args.manifest.resolve(strict=True)
    manifest = json.loads(manifest_path.read_text())
    assert hashlib.sha256(Path(manifest["board_source"]).read_bytes()).hexdigest() == manifest["board_source_sha256"]
    flash_model_headers = {name: manifest.get("native_mcu_model_headers", {}).get(name)
        for name in ("ex1850-flash-core.h", "ex1850-flash-board.h")}
    flash_model_present = all(flash_model_headers.values())
    flash_wait_headers = {name: manifest.get("native_mcu_model_headers", {}).get(name)
        for name in ("ex1850-flash-wait-core.h", "ex1850-flash-wait-board.h")}
    flash_wait_present = all(flash_wait_headers.values())
    if (args.flash_mode == "functional" or args.flash_request_trace) and not flash_model_present:
        parser.error("selected immutable MCU build does not contain the Flash controller")
    if flash_model_present:
        for name, item in flash_model_headers.items():
            snapshot = Path(item["snapshot"])
            assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == item["sha256"]
            shutil.copy2(snapshot, directory / name)
    if flash_wait_present:
        for name, item in flash_wait_headers.items():
            snapshot = Path(item["snapshot"])
            assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == item["sha256"]
            shutil.copy2(snapshot, directory / name)
        hook = manifest["native_FLASH_TCG_wait_hook"]
        for relative, item in hook["sources"].items():
            for variant, digest_field in (("before", "original_sha256"), ("after", "patched_sha256")):
                snapshot = Path(item["original_source" if variant == "before" else "patched_source"])
                assert hashlib.sha256(snapshot.read_bytes()).hexdigest() == item[digest_field]
                retained = directory / "tcg-mmio-hook" / variant / relative
                retained.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(snapshot, retained)
        patch = Path(hook["patch_script"])
        assert hashlib.sha256(patch.read_bytes()).hexdigest() == hook["patch_script_sha256"]
        shutil.copy2(patch, directory / patch.name)
    if args.gpio_masked_readpin and "gpio_masked_readpin" not in Path(manifest["board_source"]).read_text():
        parser.error("selected immutable MCU build does not support the masked original ReadPin observer")
    if gpio_known and "gpio_pin_known_mask" not in Path(manifest["board_source"]).read_text():
        parser.error("selected immutable MCU build does not support partial GPIO input masks")
    pcal_events_present = "ex1850_pcal_pin_event" in Path(manifest["board_source"]).read_text()
    if args.pcal_pin_event and not pcal_events_present:
        parser.error("selected MCU build does not support timed PCAL inputs")
    if args.pcal_host_input_file and "ex1850_pcal_host_set" not in Path(manifest["board_source"]).read_text():
        parser.error("selected MCU build does not support host PCAL pads")
    if args.gpio_host_input_file and "ex1850_gpio_host_set" not in Path(manifest["board_source"]).read_text():
        parser.error("selected MCU build does not support host GPIO pads")
    rtc_contract = manifest.get("native_RTC_contract")
    rtc_schema = rtc_contract.get("schema") if rtc_contract else None
    rtc_present = rtc_schema in ("stm32f412.rtc-lse-shadow.v1", "stm32f412.rtc-lse-alarm-exti17.v1")
    rtc_alarm_present = rtc_schema == "stm32f412.rtc-lse-alarm-exti17.v1"
    if rtc_contract and not rtc_present:
        parser.error("selected immutable MCU build has an unknown RTC contract schema")
    if rtc_present:
        header = manifest["native_mcu_model_headers"]["ex1850-rtc-core.h"]
        assert header == rtc_contract["core"]
        assert hashlib.sha256(Path(header["snapshot"]).read_bytes()).hexdigest() == header["sha256"]
        shutil.copy2(header["snapshot"], directory / "ex1850-rtc-core.h")
    if rtc_alarm_present:
        header = manifest["native_mcu_model_headers"]["ex1850-rtc-exti-core.h"]
        assert header == rtc_contract["exti_core"]
        assert hashlib.sha256(Path(header["snapshot"]).read_bytes()).hexdigest() == header["sha256"]
        assert (rtc_contract["EXTI_line"], rtc_contract["NVIC_IRQ"]) == (17, 41)
        shutil.copy2(header["snapshot"], directory / "ex1850-rtc-exti-core.h")
    binary = (ROOT / manifest["binary"]).resolve(strict=True)
    assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest["binary_sha256"]
    source = INPUT.read_bytes()
    assert hashlib.sha256(source).hexdigest() == EXPECTED_SHA
    battery_config = None
    if args.battery_config_trace:
        from ex1850_battery_config import ConfigObserver
        battery_config = ConfigObserver(source)
    battery_task = None
    if args.battery_task_trace:
        from ex1850_battery_task import TaskObserver
        battery_task = TaskObserver(source)
    auxiliary_power = None
    if args.auxiliary_power_spec:
        from ex1850_auxiliary_power import AuxiliaryPower
        auxiliary_power = AuxiliaryPower(args.auxiliary_power_spec, source, directory)
        shutil.copy2(args.auxiliary_power_spec, directory / "auxiliary-power-spec.json")
        shutil.copy2(Path(__file__).with_name("ex1850_auxiliary_power.py"),
                     directory / "ex1850_auxiliary_power.py")
    protected_path = Path(os.environ.get("Z62_EXPEED_MANIFEST", str(WORK / "z6ii/build-manifest.json")))
    protected_bytes = protected_path.read_bytes()
    protected = json.loads(protected_bytes)
    protected_binary = Path(protected["binary"])
    assert hashlib.sha256(protected_binary.read_bytes()).hexdigest() == protected["binary_sha256"]
    script = Path(__file__).read_bytes()
    (directory / "probe-source.py").write_bytes(script)
    shutil.copy2(Path(__file__).with_name("run_evidence.py"), directory / "run_evidence.py")
    shutil.copy2(Path(manifest["board_source"]), directory / "board-source.c")
    shutil.copy2(manifest_path, directory / "build-manifest.json")
    debug_clock = manifest.get("host_debug_clock_guard")
    assert debug_clock, "Rebuild the isolated MCU QEMU with the host debug clock guard"
    auxiliary_sources = []
    def selected_auxiliary(saved_name, original_path, expected):
        immutable = binary.parent / saved_name
        path = immutable if immutable.exists() else Path(original_path)
        assert hashlib.sha256(path.read_bytes()).hexdigest() == expected, str(path)
        auxiliary_sources.append(dict(path=str(path), sha256=expected,
            basis="selected_immutable_binary_snapshot" if path == immutable else "hash_exact_legacy_source"))
        shutil.copy2(path, directory / saved_name)
    selected_auxiliary("icount-common.c", debug_clock["patched_source"], debug_clock["patched_sha256"])
    selected_auxiliary("exmcu_debug_clock_patch.py", debug_clock["patch_script"], debug_clock["patch_script_sha256"])
    deep_sleep = manifest.get("native_deep_sleep_boundary_guard")
    assert deep_sleep, "Rebuild the isolated MCU QEMU with the native SLEEPDEEP boundary guard"
    for saved_name, name, digest_field in (("armv7m_nvic.c", "patched_source", "patched_sha256"),
                               ("armv7m_nvic.original.c", "original_source", "original_sha256"),
                               ("exmcu_deepsleep_guard_patch.py", "patch_script", "patch_script_sha256"),
                               ("armv7m_nvic.h", "header_source", "header_sha256"),
                               ("armv7m_nvic.original.h", "original_header_source", "original_header_sha256")):
        selected_auxiliary(saved_name, deep_sleep[name], deep_sleep[digest_field])
    port, qmp_port = free_port(), free_port()
    command = [str(binary), "-M", "nikon-ex1850-reset", "-kernel", str(INPUT),
        "-display", "none", "-serial", "none", "-monitor", "none", "-nic", "none",
        "-no-reboot", "-trace", "qemu_system_shutdown_request",
        "-S", "-gdb", f"tcp:127.0.0.1:{port}",
        "-qmp", f"tcp:127.0.0.1:{qmp_port},server=on,wait=off", "-accel", "tcg",
        "-icount", "shift=3,align=off,sleep=off", "-d", "guest_errors,unimp"]
    if args.nvic_write_trace == "on":
        command.extend(("-trace", "nvic_sysreg_write"))
    serial_peer = None
    if args.rng_public_word:
        assert manifest.get('native_public_RNG_contract', {}).get('environment') == 'EX1850_PUBLIC_RNG_WORDS', (
            'selected immutable MCU build has no explicit external RNG word contract')
    if args.usart1_negative_peer:
        assert manifest.get('native_USART1_contract', {}).get('chardev_id') == 'ex1850-usart1', (
            'selected immutable MCU build has no external USART1 clean byte-stream contract')
        from ex1850_usart1_peer import SerialNegativePeer
        serial_peer = SerialNegativePeer(directory / 'USART1-peer',
                                         args.usart1_negative_peer, args.usart1_peer_max_replies)
        command.extend(('-chardev', serial_peer.chardev))
    elif args.usart1_battery_spec:
        assert manifest.get('native_USART1_contract', {}).get('chardev_id') == 'ex1850-usart1'
        from ex1850_battery_peer import SerialBatteryPeer
        serial_peer = SerialBatteryPeer(directory / 'USART1-peer', args.usart1_battery_spec,
                                       args.rng_public_word, args.usart1_peer_max_replies)
        command.extend(('-chardev', serial_peer.chardev))
    report = dict(camera_access=False, main_EXPEED_guest_accessed=False,
        full_NVIC_sysreg_write_trace_enabled=args.nvic_write_trace == "on",
        QEMU_shutdown_trace_enabled=True,
        selected_auxiliary_sources=auxiliary_sources,
        source=str(INPUT), source_sha256=EXPECTED_SHA, original_reset_vector_used=True,
        CPU_reset_SP_PC_verified=False, original_ROM_in_memory_verified=False,
        full_native_MCU_boot_verified=False, full_power_on_boot_verified=False,
        instruction_bytes_modified=False, host_firmware_instruction_patches=False,
        diagnostic_function_calls=[],
        guest_RAM_or_register_fixtures=[], MCU_packet_replay=[],
        diagnostic_RAM_field_scope="EXPEED diagnostic replay; explicit MCU auxiliary input is reported separately",
        MCU_auxiliary_power=auxiliary_power.record if auxiliary_power else None,
        actual_host_guest_state_write_count=0,
        factory_configuration_supplied=False, ready_or_success_flag_fixtures=[],
        ARMv7M_NVIC_bitband_implementation="QEMU 10.2.4 architectural models",
        SRAM_bytes_hypothesis=RAM_SIZE, SRAM_power_up_zero_physically_verified=False,
        FLASH_controller_model_present=flash_model_present,
        FLASH_selected_model_headers=flash_model_headers,
        FLASH_bounded_TCG_wait_present=flash_wait_present,
        FLASH_selected_wait_headers=flash_wait_headers,
        FLASH_functional_experiment_enabled=args.flash_mode == "functional",
        FLASH_explicit_functional_inputs=flash_inputs,
        FLASH_voltage_protection_latency_physically_verified=False,
        FLASH_scope=("supplied512KiB array; sector erase and x32 guest word stores; NOR1-to0, async virtual commit, IRQ4 and ROM-device TB invalidation; " +
            ("busy array/CR waits for aligned SRAM Thumb16 immediate word LDR/STR without IT; retry before pending IRQ; " if flash_wait_present else "busy AHB stall remains a boundary; ") +
            "fetch/vector/debugger/DMA/multiple accesses, option/OTP, mass erase and other parallelism remain boundaries"),
        FLASH_source_input_file_unchanged=None,
        initial_simulated_FLASH_snapshot=None, current_simulated_FLASH_snapshot=None,
        original_FLASH_save_requests=[], original_FLASH_save_callbacks=[],
        nominal_CPU_hz_hypothesis=manifest["reset_CPU_hz_hypothesis"],
        ROM_HSE_hz_constant=manifest["ROM_HSE_hz_constant"],
        PWR_CR_family_reset_hypothesis=manifest["PWR_CR_family_reset_hypothesis"],
        PWR_status_ready_supplied=False, icount_shift_hypothesis=3,
        PWR_control_scope="VOS, DBP, FPDS and LPDS writable latches only; original SLEEPDEEP request is a strict boundary before stock QEMU RAZ/WI; STOP clocks, wake events and CSR status remain unmodeled",
        stock_QEMU_SCR_SLEEPDEEP_RAZ_WI_is_not_a_STOP_implementation=True,
        original_SLEEPDEEP_write_is_strict_boundary=True,
        HSE_present_hypothesis=not args.without_hse,
        HSE_start_ns_hypothesis=manifest["HSE_start_ns_hypothesis"],
        PLL_lock_ns_hypothesis=manifest["PLL_lock_ns_hypothesis"],
        clock_switch_ns_hypothesis=manifest["clock_switch_ns_hypothesis"],
        oscillator_PLL_status_source="virtual-time device state machine",
        hardware_register_read_log_is_sampled=True,
        AHB1ENR_reset_zero_hypothesis=True,
        AHB2ENR_reset_zero_hypothesis=True,
        APB2ENR_reset_zero_hypothesis=True,
        TIM5_modeled_feature_scope="internal upcounter, PSC preload/UG, ARR, CEN and hardware UIF; nonzero IRQ/trigger/slave control stops",
        TIM11_modeled_feature_scope="16-bit internal upcounter, APB2 bit18 kernel clock, PSC preload/UG, ARR/CEN, frozen output compare CCR1, clocked UIF/CC1IF and DIER-driven IRQ26; external capture, pin waveforms and remapping strict",
        TIM11_IRQ26_uses_original_guest_vector_registration=True,
        TIM1_shared_IRQ_idle_scope="SR0/DIER0 under family reset, disabled event sources and no accepted activation/control writes; other accesses strict",
        TIM11_family_reset_ARR_reference=0,
        TIM5_TIM11_clock_transition_scope="counters synchronize at old HCLK/APB divisors before source/divisor changes, then reschedule at new rates; actual gate transitions freeze/resume counters",
        TIM12_model_present_in_selected_build="ex1850-tim12-core.h" in manifest.get("native_mcu_model_headers", {}),
        TIM12_model_scope="40001800 internal 16-bit upcounter, APB1 bit6, PSC/ARR preload and UG, UIF/CC1IF/CC2IF W0C, frozen output comparisons, DIER-driven shared IRQ43; trigger/capture/DMA/waveforms strict",
        TIM12_irq_source="clocked hardware SR and original guest DIER only; original NVIC vector and callbacks",
        TIM12_is_not_TIM7=True,
        GPIO_modeled_feature_scope="F4-family control latches A..H; optional static driven input IDR, uncontended GPIO outputs and analog digital-input off; alternate-function coupling, lock and dynamic edges strict",
        GPIO_external_pin_level_hypotheses={port: hex(level) for port, level in gpio_levels.items()},
        GPIO_external_input_known_masks={port: hex(gpio_known.get(port, 0xffff)) for port in gpio_levels},
        GPIO_external_pin_levels_are_camera_samples_or_reset_defaults=False,
        GPIO_board_input_levels_supplied=False,
        GPIO_original_READPIN_masked_observation_enabled=args.gpio_masked_readpin,
        GPIO_READPIN_unobserved_bits_are_zero_representatives=args.gpio_masked_readpin,
        GPIO_READPIN_original_10_bytes_checked_at_each_admitted_read=True,
        GPIO_READPIN_selected_alternate_function_and_generic_IDR_remain_strict=True,
        SYSCFG_modeled_feature_scope="EXTICR1..4 control latches, PortA family reset0 and APB2 bit14 clock gate; no board pin or EXTI event source",
        EXTI_modeled_feature_scope=("RTC17 actual internal transitions, RTSR/FTSR, sticky PR/W1C and IRQ41; original live PG6/IRQ23 contract; unknown dynamic inputs, RTC17 event wake and software triggers strict" if rtc_alarm_present else "family reset0 PR/W1C before unknown edges, IMR/EMR/RTSR/FTSR control latches; PR read after arming edges, software interrupts, external inputs and IRQs remain strict"),
        EXTI_pending_input_event_or_IRQ_supplied=False,
        APB1RSTR_modeled_feature_scope="I2C1RST/I2C2RST bits21/22 control latch and controller reset coupling; external slave/pins are not reset by the controller",
        I2C2_modeled_feature_scope="clock-gated native configuration and controller reset latches; SR1/SR2/DR, START/STOP, pads, IRQ, ACK and external data remain strict",
        I2C1_I2C2_clock_disabled_control_register_reads_zero_and_writes_ignored_family_hypothesis=True,
        DMA1_modeled_feature_scope="AHB1 bit21 gate, idle stream configuration latches, reset-empty FIFO and W1C flags; EN1 stops before any transfer, copy or completion",
        ADC1_control_scope="STM32F412 single ADC family reset, APB2 bit8 gate, common CCR and configuration; explicit voltage enables only 12-bit single regular polling or CR1 EOCIE/OVRIE NVIC IRQ18 conversion after original analog mux, ADON stability and SWSTART; clocked EOC/DR/SR W0C and RM0402 13.12.1 DMA|EOCS-gated OVR; injected, continuous, scan, watchdog, DMA and external trigger backends strict",
        ADC1_analog_input_or_conversion_EOC_supplied=False,
        ADC1_external_node_voltage_hypotheses={str(ch): mv for ch, mv in adc_levels.items()},
        ADC1_reference_millivolts_hypothesis=args.adc_vref_mv,
        ADC1_voltage_levels_are_camera_samples_or_factory_calibration=False,
        ADC1_quantization_hypothesis="ideal right-aligned12-bit floor(mV*4096/VREF), saturated4095, no noise or physical offset/gain calibration",
        ADC1_conversion_timing="public STM32F4 sample-cycle table plus12 processing cycles at actual PCLK2/ADCPRE; ADON stable for at least3us; virtual time only",
        ADC1_common_CCR_reset_family_reference=0,
        ADC1_watchdog_HTR_reset_family_reference=0xfff,
        RTC_modeled_feature_scope=("DBP/WPR, empty backup, integer-phase LSE, calendar/SSR/shadows, A/B BCD/date/weekday/MASKSS alarms, independent2-LSE control synchronizers, 2-APB W0C and EXTI17/IRQ41; wakeup/tamper/timestamp/12h/BYPSHAD/SHIFTR/calibration remain strict" if rtc_alarm_present else "DBP/WPR, empty backup, integer-phase LSE, 2-cycle INITF, 4-cycle restart, 24h BCD calendar/SSR and two-cycle graded shadow locks; alarms/wakeup/tamper/BYPSHAD/SHIFTR/calibration remain strict" if rtc_present else "DBP/WPR, empty BDCR/backup, LSE/ISR clock transitions, CR/PRER/TAFCR and 24h BCD calendar with shadow reads; alarm/wakeup/tamper/subsecond features remain strict"),
        RTC_alarm_and_EXTI17_model_present_in_selected_build=rtc_alarm_present,
        RTC_subsecond_model_present_in_selected_build=rtc_present,
        RTC_selected_contract=rtc_contract if rtc_present else None,
        RTC_calendar_reset_family_reference=dict(TR=0, DR=0x2101, PRER=0x7f00ff),
        RTC_calendar_uses_host_wall_clock=False,
        RTC_calendar_written_by_original_guest_only=True,
        I2C1_modeled_feature_scope="native configuration; opt-in pads, clocked START/SB/IRQ31, absent NACK/AF/IRQ32/STOP; per-address PCAL6524 or MAX77711-family contract; ADDR SR1/SR2 clearing; two clocked TX/RX slots; unknown external registers/data remain strict",
        I2C_device_ACK_or_external_data_supplied=False,
        I2C_external_input_data_supplied=False,
        PCAL6524_external_pin_level_hypothesis=(hex(args.pcal_pin_levels) if args.pcal_pin_levels is not None else None),
        PCAL6524_timed_external_input_events=[dict(virtual_ns=t, mask=hex(mask), levels=hex(levels))
            for t, mask, levels in args.pcal_pin_event],
        PCAL6524_timed_input_clock="MCU virtual clock from cold reset; separate from EXPEED clocks",
        PCAL6524_host_input_file=str(args.pcal_host_input_file) if args.pcal_host_input_file else None,
        PCAL6524_host_input_events=[],
        GPIO_host_input_file=str(args.gpio_host_input_file) if args.gpio_host_input_file else None,
        GPIO_host_input_events=[],
        GPIO_host_input_scope="declared polled digital input pads; unknown, output, alternate-function, armed EXTI and live PG6 changes rejected",
        PCAL6524_external_pin_levels_are_camera_sample=False,
        PCAL6524_external_pin_levels_are_documented_reset_default=False,
        I2C_candidate_device_protocol_hypothesis_enabled=args.i2c_slave == "pcal6524" or args.i2c_max77711,
        MAX77711_family_contract_enabled=args.i2c_max77711,
        MAX77711_identity_and_rail_wiring_physically_verified=False,
        MAX77711_board_hypotheses=(dict(VIO_valid=True, PHCFG1_floating=True,
            PHCFG0_floating=True, address7="0x4f") if args.i2c_max77711 else None),
        MAX77711_register_scope="B2_CNFG_D23 only: full-byte Write/Read, clamp aboveD2; automatically incrementing pointer; original-written latch; unknown pre-write OTP value",
        MAX77711_OTP_or_RNG2_supplied=False,
        MAX77711_rail_voltage_PGOOD_nRSTIO_or_EXPEED_ready_supplied=False,
        PCAL6524_identity_and_board_wiring_physically_verified=False,
        PCAL6524_board_hypotheses=(dict(power_available=True, RESET_released=True,
            ADDR_strapped_to_VSS=True, address7="0x22") if args.i2c_slave == "pcal6524" else None),
        PCAL6524_input_register_default="undefined XXXXXXXX, actual external pin level",
        I2C_bus_electrical_scenario=args.i2c_bus,
        I2C_explicit_absent_address_hypotheses=[hex(a) for a in sorted(args.i2c_absent_address)],
        I2C_global_absent_hypothesis=args.i2c_slave == "absent",
        I2C_unprovided_address_response="stop before original DR latch and ACK/NACK decision",
        I2C_bus_pad_levels_and_pullups_physically_verified=False,
        I2C_ADDR_and_transmit_TXE_BTF_unmodeled=args.i2c_slave != "pcal6524" and not args.i2c_max77711,
        I2C_receive_RXNE_BTF_DR_data_unmodeled=args.pcal_pin_levels is None and not args.i2c_max77711,
        I2C_DMA_transfer_backend_unmodeled=True,
        I2C_receive_model_feature_scope="optional PCAL inputs/registers/group pointers, timed pin edges and input latches; MAX B2_CNFG_D23 guest-written latch/sequential pointer; two clocked TX/RX slots; no PCAL hardware debounce, PMIC OTP/rail voltage/protection/PGOOD/nRSTIO",
        PCAL6524_cold_power_register_reset_hypothesis=args.i2c_slave == "pcal6524",
        PCAL6524_push_pull_outputs_have_no_external_contention_hypothesis=args.pcal_pin_levels is not None,
        PCAL6524_dynamic_pin_edges_and_input_latches_modeled=pcal_events_present,
        PCAL6524_interrupt_status_and_port_read_W1C_modeled=pcal_events_present,
        PCAL6524_interrupt_output_to_MCU_EXTI_connection_unprovided=True,
        I2C_START_pending_SB_request_model="bounded level-request coalescing during an overlapping IRQ read-modify-write; controller timing unmeasured",
        I2C_START_STOP_DR_SR1_SR2_unmodeled=args.i2c_bus == "strict",
        I2C_slave_absent_negative_control=args.i2c_slave == "absent",
        RTC_transition_cycles_hypothesis=manifest["RTC_transition_cycles_hypothesis"],
        RTC_ISR_reset_family_reference=7,
        RTC_write_protection_after_BDRST_unlocked_fixture=False,
        LSE_present_hypothesis=not args.without_lse,
        LSE_hz_family_hypothesis=manifest["LSE_hz_family_hypothesis"],
        LSE_start_ns_hypothesis=manifest["LSE_start_ns_hypothesis"],
        retained_backup_domain_supplied=False,
        RCC_BDCR_cold_zero_reset_hypothesis=True,
        RTC_calendar_or_ready_state_supplied=False,
        all_oscillator_PLL_switch_events_logged=True,
        physical_MCU_identity_and_clock_verified=False,
        passive_hardware_breakpoints=args.observe, observations=[],
        repeated_RTC_alarm_trace_enabled=args.rtc_alarm_trace,
        repeated_RTC_alarm_trace_max_hits_per_entry=32 if args.rtc_alarm_trace else 0,
        RTC_alarm_shared_exception_entry_080201fc_breakpoint_armed=False,
        RTC_alarm_route_evidence="RTC-specific dispatch/callback IPSR plus original vector and dispatch SRAM slots",
        RTC_alarm_observer_peripheral_MMIO_reads=False,
        RTC_alarm_observer_guest_callbacks_or_calendar_events_supplied=False,
        repeated_I2C_request_trace_enabled=args.i2c_request_trace,
        repeated_I2C_request_trace_max_hits_per_entry=32 if args.i2c_request_trace else 0,
        battery_config_trace_enabled=args.battery_config_trace,
        battery_config_trace_max_hits_per_entry=32 if args.battery_config_trace else 0,
        battery_config_trace_limit_reached=[], original_battery_config_events=[],
        battery_config_observer_guest_state_supplied=False,
        battery_config_observer_peripheral_MMIO_reads=False,
        battery_task_trace_enabled=args.battery_task_trace,
        battery_task_trace_max_hits_per_entry=32 if args.battery_task_trace else 0,
        original_battery_task_events=[], battery_task_trace_limit_reached=[],
        battery_task_observer_guest_state_supplied=False,
        battery_task_observer_peripheral_MMIO_reads=False,
        selected_observation_addresses=[hex(address) for address in points] if args.observe else [],
        host_debug_clock_guard_enabled=args.debug_clock_guard == "on",
        host_debug_clock_warp_audit_enabled=args.debug_warp_audit,
        normal_guest_WFI_timer_warp_unchanged=True,
        MCU_build=manifest, preserved_EXPEED_build_sha256=protected["binary_sha256"],
        command=command, script_sha256=hashlib.sha256(script).hexdigest(),
        budget_seconds=args.seconds, first_unmodeled=None,
        USART1_external_peer_enabled=serial_peer is not None,
        USART1_external_peer_mode=serial_peer.mode if serial_peer else None,
        USART1_external_peer_input_is_original_battery_capture=False,
        explicit_external_RNG_words=args.rng_public_word,
        external_RNG_input_classification='analyst-created synthetic external RNG words' if args.rng_public_word else None,
        USART1_battery_specification=serial_peer.specification if args.usart1_battery_spec else None,
        original_SYSRESETREQ_exits_owned_process=True,
        hardware_system_reset_reboot_not_emulated=True)
    remote = monitor = process = None
    rsp_bytes = ByteLedger(directory, "RSP")
    qmp_bytes = ByteLedger(directory, "QMP")
    runtime_snapshots = directory / "debugger-runtime-sources"
    runtime_snapshots.mkdir()
    runtime_sources = []
    tool_root = (WORK / "tools").resolve()
    runtime_paths = {Path(__file__).resolve(), Path(__file__).with_name("debugger_byte_ledger.py").resolve()}
    if battery_config is not None:
        runtime_paths.add(Path(__file__).with_name('ex1850_battery_config.py').resolve())
    if battery_task is not None:
        runtime_paths.add(Path(__file__).with_name('ex1850_battery_task.py').resolve())
    if args.initial_resource_startup_barrier:
        runtime_paths.add(Path(__file__).with_name('startup_barrier.py').resolve())
    if serial_peer is not None:
        runtime_paths.add(Path(__file__).with_name('ex1850_usart1_peer.py').resolve())
    if args.usart1_battery_spec:
        runtime_paths.update(Path(__file__).with_name(name).resolve() for name in
            ('ex1850_battery_peer.py', 'ex1850_public_auth_math.py', 'ex1850_original_prng.py'))
        battery_sources = []
        for path in dict.fromkeys([str(args.usart1_battery_spec.resolve()), battery_spec['ROM']['path'],
                                  *[item['path'] for item in battery_spec['source_evidence']]]):
            raw = Path(path).read_bytes()
            digest = hashlib.sha256(raw).hexdigest()
            saved = directory / 'battery-input-source-snapshots' / (Path(path).name + '--' + digest[:16])
            saved.parent.mkdir(exist_ok=True)
            saved.write_bytes(raw)
            battery_sources.append(dict(path=path, bytes=len(raw), sha256=digest, retained_snapshot=str(saved),
                                        supplied_as_guest_RAM=False))
        report['USART1_battery_input_sources'] = battery_sources
    for module in list(sys.modules.values()):
        path = getattr(module, "__file__", None)
        if path and Path(path).suffix == ".py":
            resolved = Path(path).resolve()
            if resolved.is_relative_to(tool_root):
                runtime_paths.add(resolved)
    for path in sorted(runtime_paths):
        data = path.read_bytes()
        digest = hashlib.sha256(data).hexdigest()
        saved = runtime_snapshots / (path.name + "--" + digest[:16])
        saved.write_bytes(data)
        runtime_sources.append(dict(path=str(path), bytes=len(data), sha256=digest,
                                    retained_snapshot=str(saved)))
    report["loaded_debugger_runtime_sources"] = runtime_sources
    report["debugger_ledger_scope"] = "MCU_only_complete_API_byte_streams; not EXPEED or physical USB"
    def capture_flash(label):
        # Debugger reads are distinct from CPU accesses. Never probe the
        # array while busy: missing AHB-stall semantics must not be triggered
        # or bypassed merely to capture an observer snapshot.
        sr = int.from_bytes(remote.memory(0x40023c0c, 4), "little")
        result = dict(phase=label, SR=hex(sr), supplied_to_any_guest=False,
                      capture_is_read_only_not_save_or_boot_acceptance=True)
        if sr & (1 << 16):
            result.update(captured=False, reason="busy-array-debugger-read-skipped")
            return result
        raw = remote.memory(BASE, len(source))
        saved = directory / (label + "-simulated-FLASH.bin")
        saved.write_bytes(raw)
        result.update(captured=True, path=str(saved), bytes=len(raw),
            sha256=hashlib.sha256(raw).hexdigest(), matches_original_input=raw == source)
        report["current_simulated_FLASH_snapshot"] = result
        return result
    log_path = directory / "qemu.log"
    log = MeaningfulQemuLog(log_path)
    try:
        env = environment()
        env.pop('EX1850_PUBLIC_RNG_WORDS', None)
        if args.rng_public_word:
            env['EX1850_PUBLIC_RNG_WORDS'] = ','.join(hex(word) for word in args.rng_public_word)
        env["EX1850_HSE_PRESENT"] = "0" if args.without_hse else "1"
        env["EX1850_LSE_PRESENT"] = "0" if args.without_lse else "1"
        env["EX1850_I2C_BUS_MODE"] = args.i2c_bus
        env["EX1850_I2C_SLAVE_MODE"] = args.i2c_slave
        env["EX1850_I2C_MAX77711"] = "1" if args.i2c_max77711 else "0"
        env["EX1850_I2C_ABSENT_ADDRESSES"] = ",".join(hex(a) for a in sorted(args.i2c_absent_address))
        env["EX1850_I2C_REQUEST_PATH"] = str(directory / "unprovided-I2C-request.json")
        if args.pcal_pin_levels is not None:
            env["EX1850_PCAL_PIN_LEVELS"] = hex(args.pcal_pin_levels)
        else:
            env.pop("EX1850_PCAL_PIN_LEVELS", None)
        if args.pcal_pin_event:
            env["EX1850_PCAL_PIN_EVENTS"] = ",".join(f"{t}:{hex(mask)}:{hex(levels)}"
                for t, mask, levels in args.pcal_pin_event)
        else:
            env.pop("EX1850_PCAL_PIN_EVENTS", None)
        if gpio_levels:
            env["EX1850_GPIO_PIN_LEVELS"] = ",".join(f"{port}={hex(level)}" for port, level in sorted(gpio_levels.items()))
        else:
            env.pop("EX1850_GPIO_PIN_LEVELS", None)
        env["EX1850_GPIO_MASKED_READPIN"] = "1" if args.gpio_masked_readpin else "0"
        env["EX1850_GPIO_PIN_KNOWN_MASKS"] = ",".join(f"{port}={hex(mask)}" for port, mask in sorted(gpio_known.items()))
        if adc_levels:
            env["EX1850_ADC_PIN_MV"] = ",".join(f"{ch}={mv}" for ch, mv in sorted(adc_levels.items()))
            env["EX1850_ADC_VREF_MV"] = str(args.adc_vref_mv)
        else:
            env.pop("EX1850_ADC_PIN_MV", None)
            env.pop("EX1850_ADC_VREF_MV", None)
        env["EX1850_DEBUG_CLOCK_GUARD"] = "1" if args.debug_clock_guard == "on" else "0"
        env["EX1850_DEBUG_WARP_AUDIT"] = "1" if args.debug_warp_audit else "0"
        env["EX1850_BOUNDARY_SRAM_PATH"] = str(directory / "boundary-SRAM.bin")
        for name in ("EX1850_FLASH_FUNCTIONAL", "EX1850_FLASH_VDD_MV", "EX1850_FLASH_NWRP",
                     "EX1850_FLASH_ERASE_NS", "EX1850_FLASH_PROGRAM_NS", "EX1850_BOUNDARY_FLASH_PATH"):
            env.pop(name, None)
        env["EX1850_FLASH_FUNCTIONAL"] = "1" if args.flash_mode == "functional" else "0"
        if args.flash_mode == "functional":
            env.update(EX1850_FLASH_VDD_MV=str(args.flash_vdd_mv),
                       EX1850_FLASH_NWRP=hex(args.flash_nwrp),
                       EX1850_FLASH_ERASE_NS=str(args.flash_erase_ns),
                       EX1850_FLASH_PROGRAM_NS=str(args.flash_program_ns))
        env["EX1850_BOUNDARY_FLASH_PATH"] = str(directory / "boundary-simulated-FLASH.bin")
        report["FLASH_effective_QEMU_environment"] = {key: value for key, value in env.items()
            if key.startswith("EX1850_FLASH_") or key == "EX1850_BOUNDARY_FLASH_PATH"}
        process_ledger.attempting(command)
        process = subprocess.Popen(command, env=env, stdout=log,
            stderr=subprocess.STDOUT, cwd=directory)
        process_ledger.started(process)
        remote = AuditedRemote(port, rsp_bytes)
        monitor = AuditedQMP(qmp_port, qmp_bytes)
        host_input_sequence = 0
        host_input_state = directory / "pcal-host-state.json"
        gpio_input_sequence = 0
        gpio_input_state = directory / "gpio-host-state.json"

        def poll_host_gpio():
            nonlocal gpio_input_sequence
            path = args.gpio_host_input_file
            if not path or not path.exists():
                return
            if path.stat().st_size > 2048:
                raise ValueError("host GPIO command exceeds 2048 bytes")
            value = json.loads(path.read_text())
            sequence = value.get("sequence")
            if sequence == gpio_input_sequence:
                return
            if type(sequence) is not int or sequence != gpio_input_sequence + 1 or sequence > 128:
                raise ValueError("host GPIO commands require consecutive sequence numbers in 1..128")
            port, mask, levels = value.get("port"), value.get("mask"), value.get("levels")
            if (not isinstance(port, str) or port not in gpio_levels or
                    type(mask) is not int or type(levels) is not int or
                    not 0 < mask <= 0xffff or not 0 <= levels <= 0xffff or levels & ~mask or
                    mask & ~gpio_known.get(port, 0xffff)):
                raise ValueError("host GPIO command requires a declared port and known 16-bit masked levels")
            property_name = "gpio-pin-levels-" + port
            before = monitor.command("qom-get", dict(path="/machine", property=property_name))
            driven = (before & ~mask) | levels
            monitor.command("qom-set", dict(path="/machine", property=property_name, value=driven))
            after = monitor.command("qom-get", dict(path="/machine", property=property_name))
            assert after == driven
            event = dict(sequence=sequence, port=port, mask=mask, levels=levels,
                         before=before, after=after, input_label=value.get("label"), running=True,
                         host_monotonic_ns=time.monotonic_ns(),
                         host_seconds_from_guest_continue=round(time.monotonic() - continued, 6),
                         guest_RAM_write=False, protocol_packet_supplied=False,
                         business_key_name_verified=False)
            report["GPIO_host_input_events"].append(event)
            gpio_input_sequence = sequence
            write_host_input_state(gpio_input_state, event)

        def poll_host_pcal():
            nonlocal host_input_sequence
            if not args.pcal_host_input_file or not args.pcal_host_input_file.exists():
                return
            # The controller replaces a complete small JSON atomically.
            value = json.loads(args.pcal_host_input_file.read_text())
            sequence = value.get("sequence")
            if sequence == host_input_sequence:
                return
            if type(sequence) is not int or sequence != host_input_sequence + 1 or sequence > 128:
                raise ValueError("host PCAL commands require consecutive sequence numbers in 1..128")
            mask, levels = value.get("mask"), value.get("levels")
            if (type(mask) is not int or type(levels) is not int or
                    not 0 < mask <= 0xffffff or not 0 <= levels <= 0xffffff or levels & ~mask):
                raise ValueError("host PCAL command requires a 24-bit mask and masked levels")
            before = monitor.command("qom-get", dict(path="/machine", property="pcal-pin-levels"))
            driven = (before & ~mask) | levels
            monitor.command("qom-set", dict(path="/machine", property="pcal-pin-levels", value=driven))
            after = monitor.command("qom-get", dict(path="/machine", property="pcal-pin-levels"))
            assert after == driven
            event = dict(sequence=sequence, mask=mask, levels=levels, before=before, after=after,
                         input_label=value.get("label"), host_monotonic_ns=time.monotonic_ns(),
                         host_seconds_from_guest_continue=round(time.monotonic() - continued, 6),
                         guest_RAM_write=False, protocol_packet_supplied=False)
            report["PCAL6524_host_input_events"].append(event)
            host_input_sequence = sequence
            # Only the latest acknowledgement is rewritten; no polling log.
            write_host_input_state(host_input_state, event)
        regs = remote.registers()
        report["initial_reset_registers"] = regs
        assert regs["r13"] == "0x20000c08" and regs["r15"] == "0x080002b4", regs
        report["CPU_reset_SP_PC_verified"] = True
        cpuid_word = int.from_bytes(remote.memory(0xE000ED00, 4), "little")
        report["initial_architectural_CPUID"] = hex(cpuid_word)
        report["CPU_type"] = manifest.get("CPU_type", "cortex-m4")
        if "CPU_CPUID" in manifest:
            assert cpuid_word == manifest["CPU_CPUID"], (cpuid_word, manifest["CPU_CPUID"])
            report["declared_CPU_CPUID_verified"] = True
        loaded = remote.memory(BASE, len(source))
        assert loaded == source
        report["original_ROM_in_memory_verified"] = True
        report["original_ROM_in_memory_sha256"] = hashlib.sha256(loaded).hexdigest()
        initial_flash_path = directory / "initial-simulated-FLASH.bin"
        initial_flash_path.write_bytes(loaded)
        report["initial_simulated_FLASH_snapshot"] = dict(path=str(initial_flash_path),
            bytes=len(loaded), sha256=hashlib.sha256(loaded).hexdigest(),
            matches_original_input=True, captured_before_first_guest_instruction=True,
            supplied_to_any_guest=False)
        report["initial_SRAM_sha256"] = hashlib.sha256(remote.memory(RAM, RAM_SIZE)).hexdigest()
        armed_points = set()
        initial_observation_points = frozenset(points)
        dynamic_return_points = set()
        pending_original_step_stop = None
        if args.observe:
            for address in points:
                assert remote.command(f"Z1,{address:x},2") == "OK"
                armed_points.add(address)
        if args.initial_resource_startup_barrier:
            from startup_barrier import ready, wait_release
            status = monitor.command('query-status')
            report['initial_resource_startup_ready'] = ready(args.initial_resource_startup_barrier,
                'MCU', status, process.pid, dict(reset_SP_PC_verified=report['CPU_reset_SP_PC_verified'],
                    original_ROM_verified=report['original_ROM_in_memory_verified']))
            report['initial_resource_startup_release'] = wait_release(
                args.initial_resource_startup_barrier, [process])
            status = monitor.command('query-status')
            if status.get('running') is not False:
                raise ValueError('MCU must remain stopped until initial resource release')
            report['initial_resource_QMP_status_before_continue'] = status
        if serial_peer is not None:
            serial_peer.wait_connected()
        if args.observe:
            remote.send("c")
        else:
            monitor.command("cont")
        continued = time.monotonic()
        end = continued + args.seconds
        if args.pcal_host_input_file:
            write_host_input_state(host_input_state, dict(sequence=0, running=True,
                 host_monotonic_ns=time.monotonic_ns(), initial_levels=args.pcal_pin_levels))
        if args.gpio_host_input_file:
            write_host_input_state(gpio_input_state, dict(sequence=0, running=True,
                host_monotonic_ns=time.monotonic_ns(), initial_levels=gpio_levels,
                known_masks={port: gpio_known.get(port, 0xffff) for port in gpio_levels}))
        while process.poll() is None and time.monotonic() < end:
            poll_host_pcal()
            poll_host_gpio()
            if args.observe and (pending_original_step_stop is not None or
                                 select.select([remote.sock], [], [], 0.01)[0]):
                try:
                    # A bare '+' acknowledges continue; it is not a stop
                    # packet. Buffer only available data and decode a stop
                    # only once its whole frame has arrived.
                    delivered_from_original_step = pending_original_step_stop is not None
                    if delivered_from_original_step:
                        stop = pending_original_step_stop
                        pending_original_step_stop = None
                    else:
                        pending = remote.sock.recv(65536)
                        if not pending:
                            raise EOFError("QEMU closed remote connection")
                        remote.buffer.extend(pending)
                        start_packet = remote.buffer.find(b"$")
                        end_packet = remote.buffer.find(b"#", start_packet + 1) if start_packet >= 0 else -1
                        if end_packet < 0 or len(remote.buffer) < end_packet + 3:
                            continue
                        stop = remote.receive()
                except (EOFError, ConnectionResetError) as closed:
                    # The strict board exits rather than returning unknown
                    # MMIO. Its GDB socket can close before poll() sees exit66.
                    report["GDB_transport_closed_at_process_boundary"] = str(closed)
                    process.wait(timeout=1)
                    break
                if stop.startswith(("W", "X")):
                    # RSP W/X reports an exited process, not a breakpoint.
                    # No register request is valid after native SYSRESETREQ
                    # has made this -no-reboot process exit.
                    report["GDB_process_exit_notification"] = stop
                    process.wait(timeout=1)
                    break
                registers = remote.registers()
                address = int(registers["r15"], 16)
                assert address in points, (stop, registers)
                assert address in armed_points, (stop, registers, armed_points)
                offset = address - BASE
                original = source[offset:offset + 16]
                assert remote.memory(address, 16) == original
                report["observations"].append(dict(address=hex(address),
                    name=points[address], stop=stop, registers=registers,
                    observation_sequence=len(report['observations']) + 1,
                    host_elapsed_seconds=round(time.monotonic() - continued, 6),
                    HAL_tick=int.from_bytes(remote.memory(0x20020400, 4), 'little') if battery_config else None,
                    stopped_after_original_step=delivered_from_original_step,
                    original_ROM_bytes=original.hex(),
                    QMP_status_while_observing=monitor.command("query-status")))
                observation_hits[address] = observation_hits.get(address, 0) + 1
                if battery_config is not None:
                    events = battery_config.on_stop(remote, address, registers, report['observations'][-1])
                    if events:
                        report['observations'][-1]['original_battery_config_events'] = events
                        report['original_battery_config_events'].extend(events)
                    if battery_task is not None and battery_task.activate(events):
                        report['battery_task_trace_activation'] = battery_task.activation
                        for point, label in BATTERY_TASK_POINTS.items():
                            points[point] = label
                            if point not in armed_points:
                                assert remote.command(f'Z1,{point:x},2') == 'OK'
                                armed_points.add(point)
                if battery_task is not None:
                    task_events = battery_task.on_stop(remote, address, registers, report['observations'][-1])
                    if task_events:
                        report['observations'][-1]['original_battery_task_events'] = task_events
                        report['original_battery_task_events'].extend(task_events)
                if battery_config is not None:
                    # A return address can serve both observers or an existing
                    # ROM point. Reconcile their union after both have consumed
                    # this stop, so one observer cannot disarm the other's return.
                    config_returns = battery_config.return_points()
                    task_returns = battery_task.return_points() if battery_task is not None else set()
                    wanted_returns = config_returns | task_returns
                    for point in sorted(wanted_returns):
                        if point not in points:
                            points[point] = 'original battery return from actual LR'
                        dynamic_return_points.add(point)
                        if point not in armed_points and observation_hits.get(point, 0) < BATTERY_CONFIG_MAX_HITS:
                            assert remote.command(f'Z1,{point:x},2') == 'OK'
                            armed_points.add(point)
                    static_points = initial_observation_points
                    if battery_task is not None and battery_task.activation is not None:
                        static_points = static_points | BATTERY_TASK_POINTS.keys()
                    for point in sorted((dynamic_return_points & armed_points) -
                                        wanted_returns - static_points - {address}):
                        assert remote.command(f'z1,{point:x},2') == 'OK'
                        armed_points.remove(point)
                if auxiliary_power is not None:
                    event = auxiliary_power.on_stop(remote, address, registers)
                    if event is not None:
                        report["observations"][-1]["MCU_auxiliary_power_event"] = event
                        report["actual_host_guest_state_write_count"] = auxiliary_power.record["actual_guest_state_write_count"]
                if address == 0x08024836:
                    # Original 08024832 BL08023824 returns here (MOV r4,r0).
                    # Retain the first 21-byte TX / 29-byte RX transaction's
                    # public control fields only; no auth C/k/H/RX body reads.
                    assert source[0x24836:0x24838] == bytes.fromhex('0446')
                    assert observation_hits[address] == 1
                    public_fields = []
                    for name, start, length in (
                            ('transaction-control', 0x2001F4E8, 6),
                            ('public-TX-and-transport-state', 0x2001FB40, 64),
                            ('power-result-control', 0x2001F440, 5),
                            ('power-status-public', 0x2001F734, 5),
                            ('authentication-response-adjacent-byte-not-status', 0x2001F49F, 1)):
                        raw = remote.memory(start, length)
                        assert len(raw) == length
                        public_fields.append(dict(name=name, address=hex(start),
                            bytes=length, hex=raw.hex()))
                    lengths = bytes.fromhex(public_fields[0]['hex'])
                    context = dict(schema='original-first-auth-public-return/1',
                        entry=hex(address), occurrence=1, returned_R0=registers['r0'],
                        TX_length=lengths[1], RX_length=lengths[3],
                        transaction_21_29_confirmed=lengths[1] == 21 and lengths[3] == 29,
                        original_instruction_bytes='0446', public_fields=public_fields,
                        total_public_RAM_bytes=81, private_auth_RAM_read=False,
                        authentication_reply_supplied=bool(args.usart1_battery_spec and
                            serial_peer.protocol.counts['authentication_replies']),
                        scope='Original UART transport return; not the later authentication comparator result',
                        supplied_to_any_guest=False)
                    report['observations'][-1]['original_first_auth_public_return'] = context
                    report['original_first_auth_public_return'] = context
                if address in (0x08023ED4, 0x08023FAE):
                    # The unchanged comparator returns bool at ED4. FAE is
                    # after the original body[0]=1 store; its restored R0 is
                    # the caller argument and is not an authentication bool.
                    body_address = int(registers['r4'], 16)
                    assert RAM <= body_address <= RAM + RAM_SIZE - 64
                    raw = remote.memory(body_address, 64)
                    context = dict(entry=hex(address), body_address=hex(body_address),
                        body_hex=raw.hex(), ready=raw[0],
                        comparator_result_stored=int.from_bytes(raw[4:8], 'little'),
                        error=int.from_bytes(raw[0x14:0x18], 'little', signed=True),
                        battery_type=raw[0x29], status=raw[0x2c],
                        original_ROM_bytes=original.hex(), guest_state_written=False,
                        live_nonce_or_H_read=False)
                    if address == 0x08023ED4:
                        assert source[0x23ED4:0x23ED6] == bytes.fromhex('6060')
                        context.update(comparator_return=int(registers['r0'], 16),
                            scope='Original bool returned by 0804261E before body+4 store')
                        key = 'original_battery_authentication_comparator'
                    else:
                        assert source[0x23FAA:0x23FAE] == bytes.fromhex('84f800b0')
                        assert source[0x23FAE:0x23FB2] == bytes.fromhex('bde8ff9f')
                        context.update(scope='Original authentication and identity tail after body[0] store; R0 excluded')
                        key = 'original_battery_authentication_completion'
                    report['observations'][-1][key] = context
                    report[key] = context
                if address in (0x080244E0, 0x080247CC):
                    # Both unchanged builders return from BL08023824 here,
                    # before MOV r4,r0. Read only public op89 TX/RX and state;
                    # no authentication nonce, H, debugger store or call.
                    import struct
                    assert source[offset:offset + 2] == bytes.fromhex('0446')
                    root = struct.unpack_from('<I', source, 0x23934)[0]
                    body_address = int(registers['r5'], 16)
                    assert RAM <= root and root + 0x8C <= RAM + RAM_SIZE
                    assert RAM <= body_address and body_address + 64 <= RAM + RAM_SIZE
                    control = remote.memory(root, 6)
                    assert control[1] == 18 and control[3] == 4
                    tx = remote.memory(root + 0x70, 18)
                    rx = remote.memory(root + 0x88, 4)
                    assert tx[:3] == bytes.fromhex('02890e')
                    body = remote.memory(body_address, 64)
                    context = dict(schema='original-cmd89-transaction-return/1',
                        entry=hex(address), occurrence=observation_hits[address],
                        observation_sequence=report['observations'][-1]['observation_sequence'],
                        host_elapsed_seconds=report['observations'][-1]['host_elapsed_seconds'],
                        HAL_tick=report['observations'][-1]['HAL_tick'],
                        builder_entry=('0x080243dc' if address == 0x080244E0 else '0x080246c4'),
                        common_validator='0x08023824', returned_R0=int(registers['r0'], 16),
                        transaction_root=hex(root), control_hex=control.hex(),
                        TX_hex=tx.hex(), RX_hex=rx.hex(),
                        original_instruction_bytes='0446', body_address=hex(body_address),
                        body_hex=body.hex(), ready=body[0],
                        error=int.from_bytes(body[0x14:0x18], 'little', signed=True),
                        body_mode=body[0x2E], info72_address='0x2001f4a0',
                        info72_hex=remote.memory(0x2001F4A0, 72).hex(),
                        auxiliary2_address='0x2000ed99',
                        auxiliary2_hex=remote.memory(0x2000ED99, 2).hex(),
                        guest_state_written=False, live_nonce_or_H_read=False,
                        scope='Original op89 common validator returned to its real caller; battery reply remains synthetic')
                    report['observations'][-1]['original_cmd89_transaction_return'] = context
                    report.setdefault('original_cmd89_transaction_returns', []).append(context)
                if address in CAPCOM_STATUS_POINTS:
                    stack = int(registers["r13"], 16)
                    parameter_register = ("r1" if address == 0x08036868 else
                                          "r0" if address == 0x08036B70 else "r7")
                    parameter = int(registers[parameter_register], 16)
                    context = dict(schema="original-MCU-CAPCOM-status-observer/1",
                        entry=hex(address), occurrence=observation_hits[address],
                        caller_return=registers["r14"],
                        original_event=(registers["r0"] if address == 0x08036868 else None),
                        parameter_register=parameter_register,
                        parameter_address=hex(parameter),
                        parameter_bytes=(remote.memory(parameter, 16).hex()
                            if RAM <= parameter and parameter + 16 <= RAM + RAM_SIZE else None),
                        stack_address=hex(stack),
                        stack_bytes=(remote.memory(stack, 64).hex()
                            if RAM <= stack and stack + 64 <= RAM + RAM_SIZE else None),
                        property36_byte=(remote.memory(stack, 1).hex()
                            if address in (0x08036B84, 0x08036BA8, 0x08036BCE) else None),
                        CAPCOM_state_2001359c=remote.memory(0x2001359c, 0x40).hex(),
                        tag1_record_2001372c=remote.memory(0x2001372c, 5).hex(),
                        HAL_tick_20020400=remote.memory(0x20020400, 4).hex(),
                        peripheral_MMIO_read_by_debugger=False,
                        supplied_to_any_guest=False)
                    report["observations"][-1]["original_CAPCOM_status_context"] = context
                if args.rtc_alarm_trace and address in RTC_ALARM_POINTS:
                    context = dict(schema="original-RTC-alarm-observer.v1",
                        entry=hex(address), occurrence=observation_hits[address],
                        IPSR_from_xPSR=int(registers["cpsr"], 16) & 0x1ff,
                        r0=registers["r0"], r1=registers["r1"], r2=registers["r2"],
                        caller_return=registers["r14"],
                        relocated_IRQ41_vector_200000e4=remote.memory(0x200000e4, 4).hex(),
                        first_dispatch_20022e14=remote.memory(0x20022e14, 4).hex(),
                        second_dispatch_2000f474=remote.memory(0x2000f474, 4).hex(),
                        RTC_callbacks_handle_and_worker_20017f60=remote.memory(0x20017f60, 0x80).hex(),
                        last_SYS_calendar_2000fac6=remote.memory(0x2000fac6, 6).hex(),
                        BLX_callback_R2=(registers["r2"] if address == 0x08039468 else None),
                        peripheral_MMIO_read_by_debugger=False, supplied_to_any_guest=False)
                    if address == 0x0803A284:
                        pointer = int(registers["r1"], 16)
                        assert RAM <= pointer and pointer + 6 <= RAM + RAM_SIZE
                        context.update(calendar_payload_address=hex(pointer),
                            calendar_payload_bytes=remote.memory(pointer, 6).hex(),
                            original_event_argument=registers["r0"])
                    report["observations"][-1]["original_RTC_alarm_context"] = context
                    report.setdefault("original_RTC_alarm_observations", []).append(context)
                if args.flash_request_trace and address in FLASH_REQUEST_POINTS:
                    import struct
                    occurrence = observation_hits[address]
                    flash_snapshot = capture_flash(f"flash-observer-{address:08x}-{occurrence:02d}")
                    context = dict(entry=hex(address), occurrence=occurrence,
                        flash_snapshot=flash_snapshot, original_r0=registers["r0"],
                        original_r1=registers["r1"], caller_return=registers["r14"],
                        service_root_20014038=remote.memory(0x20014038, 0xf0).hex(),
                        queued_descriptor_20011744=remote.memory(0x20011744, 16).hex(),
                        supplied_to_any_guest=False)
                    if address == 0x08032120:
                        pointer = int(registers["r0"], 16)
                        assert RAM <= pointer and pointer + 16 <= RAM + RAM_SIZE
                        descriptor = remote.memory(pointer, 16)
                        data, length, callback = struct.unpack_from("<3I", descriptor, 4)
                        assert 0 < length <= RAM_SIZE and RAM <= data and data + length <= RAM + RAM_SIZE
                        payload = remote.memory(data, length)
                        saved = directory / f"flash-request-{occurrence:02d}-source.bin"
                        saved.write_bytes(payload)
                        context.update(descriptor_address=hex(pointer), descriptor_bytes=descriptor.hex(),
                            descriptor_byte0=descriptor[0], unused_header_bytes_not_interpreted=descriptor[1:4].hex(),
                            source_address=hex(data), source_bytes=length, callback=hex(callback),
                            source_snapshot=dict(path=str(saved), bytes=len(payload),
                                sha256=hashlib.sha256(payload).hexdigest(), prefix=payload[:64].hex()),
                            descriptor_is_queued_request_not_completed_save=True)
                        report["original_FLASH_save_requests"].append(context)
                    else:
                        context.update(return_value_at_callback_entry=(int(registers["r0"], 16)
                            if address == 0x0802EE54 else None),
                            stored_result_20014048=int.from_bytes(remote.memory(0x20014048, 4), "little"),
                            event_dispatch_arguments_observed=address == 0x0802EE60)
                        report["original_FLASH_save_callbacks"].append(context)
                    report["observations"][-1]["original_FLASH_save_context"] = context
                if args.i2c_request_trace and address in I2C_REQUEST_POINTS:
                    import struct
                    handle = int(registers["r0"], 16)
                    stack = int(registers["r13"], 16)
                    is_memory = address in (0x08044648, 0x080449B0)
                    is_write = address in (0x08044200, 0x080449B0)
                    raw_stack = remote.memory(stack, 32)
                    if is_memory:
                        data, size = struct.unpack_from("<2I", raw_stack)
                    else:
                        data, size = (int(registers[k], 16) for k in ("r2", "r3"))
                    descriptor = dict(
                        entry=hex(address), occurrence=observation_hits[address],
                        operation=("memory-" if is_memory else "master-") + ("write" if is_write else "read"),
                        handle=hex(handle), DevAddress=registers["r1"],
                        address7=(int(registers["r1"], 16) & 0xff) >> 1,
                        MemAddress=registers["r2"] if is_memory else None,
                        MemAddressSize=registers["r3"] if is_memory else None,
                        pData=hex(data), Size=size, caller_return=registers["r14"],
                        stack_bytes=raw_stack.hex(),
                        original_handle_bytes=(remote.memory(handle, 96).hex()
                            if RAM <= handle and handle + 96 <= RAM + RAM_SIZE else None),
                        planned_data_buffer_before_transfer=(remote.memory(data, min(size, 256)).hex()
                            if 0 < size <= RAM_SIZE and RAM <= data and data + min(size, 256) <= RAM + RAM_SIZE else None),
                        descriptor_is_original_request_not_completed_wire_transaction=True,
                        buffer_is_pretransfer_memory_not_external_receive_result=True,
                        supplied_to_any_guest=False)
                    report["observations"][-1]["repeated_original_I2C_request"] = descriptor
                    report.setdefault("original_I2C_request_descriptors", []).append(descriptor)
                if address == 0x08038890:
                    pointer = int(registers["r7"], 16)
                    report["observations"][-1]["original_PMIC_readback_result"] = dict(
                        returned_R0=registers["r0"], comparison_R4=registers["r4"],
                        failed_rounds_R6=registers["r6"], sample_pointer=hex(pointer),
                        samples=(remote.memory(pointer, 3).hex()
                            if RAM <= pointer and pointer + 3 <= RAM + RAM_SIZE else None),
                        source="read-only actual original return context, never supplied to guest")
                if address == 0x08020084:
                    # Read-only capture after the actual reset-driven C
                    # initializer; never replayed into a guest.
                    initialized = remote.memory(RAM, RAM_SIZE)
                    saved_ram = directory / "original-reset-application-SRAM.bin"
                    saved_ram.write_bytes(initialized)
                    import struct
                    report["native_C_initialized_SRAM_snapshot"] = dict(
                        path=str(saved_ram), sha256=hashlib.sha256(initialized).hexdigest(),
                        bytes=len(initialized), captured_at_original_application_entry=True,
                        supplied_to_any_guest=False,
                        software_HCLK_word_20037FF0=struct.unpack_from("<I", initialized, 0x37FF0)[0],
                        tick_word_20020400=struct.unpack_from("<I", initialized, 0x20400)[0],
                        relocated_vector_bytes=initialized[:0x1C4].hex(),
                        original_vector_copy_matches=initialized[:0x1C4] == source[:0x1C4])
                if address in (0x0804219C, 0x080498F8, 0x08045AE6):
                    report["observations"][-1]["original_TIM5_handle_2000F534"] = remote.memory(0x2000F534, 0x40).hex()
                if address == 0x08000650:
                    report["observations"][-1]["RAM_tick_before_original_increment"] = remote.memory(0x20020400, 4).hex()
                    report["observations"][-1]["IPSR_from_xPSR"] = int(registers["cpsr"], 16) & 0x1ff
                if address == 0x08045000:
                    pointer = int(registers["r0"], 16)
                    assert RAM <= pointer and pointer + 64 <= RAM + RAM_SIZE
                    report["observations"][-1]["original_RTC_handle_address"] = hex(pointer)
                    report["observations"][-1]["original_RTC_handle_bytes"] = remote.memory(pointer, 64).hex()
                if address in (0x080394B4, 0x080394BE, 0x080394E2):
                    # Original MOV r1,SP at 080394AC; ADD r1,SP,#14 at
                    # 080394B6. The observed SP is the caller's current frame.
                    assert source[0x394A4:0x394AE] == bytes.fromhex("10b586b0044600226946")
                    assert source[0x394B6:0x394B8] == bytes.fromhex("05a9")
                    assert source[0x394E0:0x394E4] == bytes.fromhex("607106b0"), "Original STRB r0,[r4,#5] / ADD SP,#24 byte identity"
                    stack = int(registers["r13"], 16)
                    output_pointer = int(registers["r4"], 16)
                    assert RAM <= stack and stack + 0x18 <= RAM + RAM_SIZE
                    assert RAM <= output_pointer and output_pointer + 6 <= RAM + RAM_SIZE
                    report["observations"][-1]["original_RTC_read_context"] = dict(
                        schema="original-RTC-read-observer.v2",
                        caller="0x080394A4", after_GetTime=address == 0x080394B4,
                        after_GetDate=address == 0x080394BE,
                        after_caller_output_stores=address == 0x080394E2,
                        stack_address=hex(stack), time_buffer_address=hex(stack),
                        time_buffer_bytes=remote.memory(stack, 12).hex(),
                        date_buffer_address=hex(stack + 0x14),
                        date_buffer_bytes=remote.memory(stack + 0x14, 4).hex(),
                        caller_output_address=registers["r4"],
                        caller_output_bytes=(remote.memory(output_pointer, 6).hex()
                            if address == 0x080394E2 else None),
                        decoded_from_original_instructions=True,
                        original_frame_bytes_checked=True,
                        calendar_MMIO_read_by_debugger=False, supplied_to_any_guest=False)
                if address in (0x08043688, 0x08043754):
                    pointer = int(registers["r0" if address == 0x08043688 else "r4"], 16)
                    assert RAM <= pointer and pointer + 0x60 <= RAM + RAM_SIZE
                    report["observations"][-1]["original_DMA_handle_address"] = hex(pointer)
                    report["observations"][-1]["original_DMA_handle_bytes"] = remote.memory(pointer, 0x60).hex()
                if address == 0x080005E8:
                    assert args.without_lse
                    delta = int(registers["r0"], 16)
                    assert delta > 5000, registers
                    report["observations"][-1]["native_LSE_timeout_tick_delta"] = delta
                if address == 0x08043E3C:
                    pointer = int(registers["r0"], 16)
                    assert RAM <= pointer and pointer + 96 <= RAM + RAM_SIZE
                    report["observations"][-1]["original_I2C_handle_address"] = hex(pointer)
                    report["observations"][-1]["original_I2C_handle_bytes"] = remote.memory(pointer, 96).hex()
                if address == 0x08043AC8:
                    report["observations"][-1]["original_GPIO_pin_read_request"] = dict(
                        port=registers["r0"], pin_mask=registers["r1"],
                        caller_return=registers["r14"], input_value_supplied=False,
                        native_pin_descriptor_pointers=remote.memory(0x2001F1D4, 64).hex())
                if address in (0x0802A83E, 0x080383F4):
                    pointer = int(registers["r1"], 16)
                    report["observations"][-1]["original_status_callback_payload"] = dict(
                        event=registers["r0"], payload_address=hex(pointer),
                        payload_bytes=(remote.memory(pointer, 16).hex()
                            if RAM <= pointer and pointer + 16 <= RAM + RAM_SIZE else None),
                        callback_target=(registers["r2"] if address == 0x0802A83E else None),
                        source="original guest registers and SRAM; observation never replayed")
                if address in (0x0802338C, 0x080430CA, 0x08042F3C):
                    pointer = int(registers["r0"], 16)
                    stack = int(registers["r13"], 16)
                    report["observations"][-1]["original_ADC_request_context"] = dict(
                        first_parameter_address=hex(pointer),
                        first_parameter_bytes=(remote.memory(pointer, 72).hex()
                            if RAM <= pointer and pointer + 72 <= RAM + RAM_SIZE else None),
                        original_ADC_handle_2001F3EC=remote.memory(0x2001F3EC, 72).hex(),
                        original_stack_address=hex(stack),
                        original_stack_bytes=(remote.memory(stack, 64).hex()
                            if RAM <= stack and stack + 64 <= RAM + RAM_SIZE else None),
                        analog_input_supplied=False, supplied_to_any_guest=False)
                if address in (0x0803CC8C, 0x0803CD20, 0x0803CDF8, 0x0803CD56,
                               0x0803E2C4, 0x0803E350, 0x0803E518, 0x0803E0C4, 0x080214FC):
                    report["observations"][-1]["original_ADC_IRQ_and_0803E094_context"] = dict(
                        ADC_driver_state_200183E0=remote.memory(0x200183E0, 48).hex(),
                        ADC_active_handle_20003800=remote.memory(0x20003800, 72).hex(),
                        selector_state_2001867C=remote.memory(0x2001867C, 36).hex(),
                        dispatch_table_20017CE0=remote.memory(0x20017CE0, 32).hex(),
                        supplied_to_any_guest=False)
                if address in (0x08037A5A, 0x08039270, 0x08044BDA, 0x08044C02):
                    stack = int(registers["r13"], 16)
                    report["observations"][-1]["native_power_and_KEY_context"] = dict(
                        KEY_root_200159A4=remote.memory(0x200159A4, 0x90).hex(),
                        module02_root_2001F688=remote.memory(0x2001F688, 0x120).hex(),
                        original_stack_address=hex(stack),
                        original_stack_bytes=(remote.memory(stack, 160).hex()
                            if RAM <= stack and stack + 160 <= RAM + RAM_SIZE else None),
                        supplied_to_any_guest=False)
                if address == 0x08044648:
                    import struct
                    pointer = int(registers["r0"], 16)
                    stack = int(registers["r13"], 16)
                    assert RAM <= pointer and pointer + 96 <= RAM + RAM_SIZE
                    assert RAM <= stack and stack + 32 <= RAM + RAM_SIZE
                    raw = remote.memory(stack, 32)
                    p_data, length = struct.unpack_from("<2I", raw)
                    report["observations"][-1]["original_I2C_request"] = dict(
                        handle=hex(pointer), DevAddress=registers["r1"],
                        MemAddress=registers["r2"], MemAddressSize=registers["r3"],
                        pData=hex(p_data), Size=length, stack_bytes=raw.hex(),
                        original_handle_bytes=remote.memory(pointer, 96).hex())
                if address in (0x08046FF0, 0x08047042, 0x080470A2,
                               0x0802FCD6, 0x0804469A, 0x0802FE9E, 0x08030098, 0x08043AE8, 0x08043B14):
                    report["observations"][-1]["original_I2C_driver_root_and_handle"] = remote.memory(0x2001FE94, 0x80).hex()
                if address == 0x08000612:
                    assert args.without_lse
                    request = int(registers["r0"], 16)
                    assert request & 0xffff0004 == 0x05fa0004
                    assert hashlib.sha256(remote.memory(BASE, len(source))).hexdigest() == EXPECTED_SHA
                    ram = remote.memory(RAM, RAM_SIZE)
                    import struct
                    snapshot = directory / "original-pre-SYSRESETREQ-SRAM.bin"
                    snapshot.write_bytes(ram)
                    report["original_pre_SYSRESETREQ_snapshot"] = dict(
                        path=str(snapshot), sha256=hashlib.sha256(ram).hexdigest(),
                        bytes=len(ram), supplied_to_any_guest=False,
                        original_ROM_at_reset_request_verified=True,
                        AIRCR_write_requested_by_original_instruction=hex(request),
                        HAL_tick=struct.unpack_from("<I", ram, 0x20400)[0],
                        RTOS_tick=list(struct.unpack_from("<2I", ram, 0x22D58)))
                assert remote.command(f"z1,{address:x},2") == "OK"
                armed_points.remove(address)
                config_repeat = battery_config is not None and (
                    address in BATTERY_CONFIG_POINTS or address in battery_config.return_points())
                if config_repeat and observation_hits[address] >= BATTERY_CONFIG_MAX_HITS:
                    report['battery_config_trace_limit_reached'].append(hex(address))
                task_repeat = battery_task is not None and (
                    address in BATTERY_TASK_POINTS or address in battery_task.return_points())
                if task_repeat and observation_hits[address] >= BATTERY_TASK_MAX_HITS:
                    report['battery_task_trace_limit_reached'].append(hex(address))
                if (((args.i2c_request_trace and address in I2C_REQUEST_POINTS) or
                     (args.flash_request_trace and address in FLASH_REQUEST_POINTS) or
                     (args.rtc_alarm_trace and address in RTC_ALARM_POINTS) or
                     config_repeat or
                     task_repeat or
                     (args.usart1_battery_spec and address in (0x080244E0, 0x080247CC)))
                        and observation_hits[address] < 32):
                    # QEMU hardware breakpoints can stop again at the same
                    # entry on plain continue. Execute its unchanged original
                    # instruction once with the point removed, then re-arm it
                    # for a subsequent real invocation. No register/RAM write.
                    step_reply = remote.command("s")
                    after_step = remote.registers()
                    assert int(after_step["r15"], 16) != address, (step_reply, after_step)
                    report["observations"][-1]["repeated_point_rearm"] = dict(
                        original_instruction_executed=True, step_reply=step_reply,
                        PC_after_original_step=after_step["r15"],
                        direct_RAM_or_register_fixture=False)
                    assert remote.command(f"Z1,{address:x},2") == "OK"
                    armed_points.add(address)
                    if int(after_step['r15'], 16) in armed_points:
                        # A tail branch can step directly onto the next armed
                        # observer. Process that actual stopped state before
                        # continuing, rather than silently skipping the event.
                        pending_original_step_stop = step_reply
                if pending_original_step_stop is None:
                    remote.send("c")
            else:
                time.sleep(0.01)
        if process.poll() is None:
            if args.observe:
                if pending_original_step_stop is None:
                    # Finish the outstanding RSP continue before querying
                    # registers. This stops execution; it changes no guest state.
                    remote.sock.sendall(b"\x03")
                    report["budget_RSP_interrupt_reply"] = remote.receive()
                else:
                    # A completed original step already stopped on another
                    # armed point. There is no outstanding continue or stop
                    # reply to drain; keep this unfinished event unverified.
                    report["budget_pending_original_step_stop"] = dict(
                        stop_reply=pending_original_step_stop,
                        stop_already_received=True,
                        observer_event_processed=False,
                        guest_state_written=False)
            monitor.command("stop")
            report["budget_reached"] = True
            report["budget_stop_registers"] = remote.registers()
            report["budget_stop_RAM_tick_word"] = remote.memory(0x20020400, 4).hex()
            report["budget_stop_module_getter_table_prefix"] = remote.memory(0x2000D018, 16).hex()
            ram = remote.memory(RAM, RAM_SIZE)
            snapshot = directory / "budget-SRAM.bin"
            snapshot.write_bytes(ram)
            report["budget_SRAM_snapshot"] = dict(path=str(snapshot), bytes=len(ram),
                sha256=hashlib.sha256(ram).hexdigest(), supplied_to_any_guest=False,
                capture_is_read_only_budget_observation_not_boot_success=True)
            if flash_model_present:
                report["budget_simulated_FLASH_snapshot"] = capture_flash("budget")
                report["original_ROM_at_budget_still_verified"] = (
                    report["budget_simulated_FLASH_snapshot"].get("matches_original_input"))
            else:
                report["original_ROM_at_budget_still_verified"] = remote.memory(BASE, len(source)) == source
        else:
            report["budget_reached"] = False
        report["probe_completed"] = True
        if battery_config is not None:
            report['battery_config_trace_completion'] = dict(
                observed_events=len(battery_config.events),
                unmatched_conversion_entries=sum(len(v) for v in battery_config.conversions.values()),
                unmatched_copy_entries=sum(len(v) for v in battery_config.copies.values()),
                pending_return_points=[hex(p) for p in sorted(battery_config.return_points())],
                guest_state_written=False, peripheral_MMIO_read_by_debugger=False,
                scope='Bounded stopped-state observation; unfinished calls remain unverified')
        if battery_task is not None:
            report['battery_task_trace_completion'] = battery_task.completion()
    except Exception as error:
        report.update(error=str(error), traceback=traceback.format_exc())
    finally:
        if process is not None and process.poll() is None:
            try:
                if monitor is not None:
                    monitor.command("quit")
                process.wait(timeout=3)
            except Exception:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        if serial_peer is not None:
            report['USART1_external_peer'] = serial_peer.finish()
            if report['USART1_external_peer']['error']:
                report['error'] = report['USART1_external_peer']['error']
        if remote is not None:
            remote.sock.close()
        if monitor is not None:
            monitor.close()
        if args.gpio_host_input_file:
            state_path = directory / "gpio-host-state.json"
            state = json.loads(state_path.read_text()) if state_path.exists() else dict(sequence=0)
            state.update(running=False, owned_QEMU_exited=process is not None and process.poll() is not None)
            write_host_input_state(state_path, state)
        if auxiliary_power is not None:
            report["MCU_auxiliary_power"] = auxiliary_power.finish()
            report["actual_host_guest_state_write_count"] = auxiliary_power.record["actual_guest_state_write_count"]
        rsp_bytes.finish()
        qmp_bytes.finish()
        report["debugger_byte_ledgers"] = dict(RSP=rsp_bytes.summary(), QMP=qmp_bytes.summary())
        report["debugger_connections_initialized"] = dict(RSP=remote is not None, QMP=monitor is not None)
        log.close()
        report["log_retention"] = log.summary()
        log_events, report["log_summary"], complete_log = collect_native_log(log_path)
        report['native_wire_boundary_lines'] = log_events['native_wire_boundary_lines']
        report["first_native_wire_boundary"] = next(
            iter(report["native_wire_boundary_lines"]), None)
        report["first_hardware_boundary_line"] = complete_log["first_boundary"]
        matches = complete_log["unmodeled"]
        device_events = complete_log["device_events"]
        assert len(matches) + len(device_events) <= 1
        if matches:
            op, address, size, value, pc = matches[0]
            report["first_unmodeled"] = dict(operation=op, address="0x" + address,
                bytes=int(size), attempted_write_value="0x" + value, pc="0x" + pc,
                process_stopped_before_unknown_read_return=True)
        if device_events:
            device, device_address, device_register = device_events[0]
            received_total = complete_log["received_total"]
            report["first_unmodeled"] = dict(operation="device_receive_event",
                device=device, address7="0x" + device_address, register="0x" + device_register,
                address=None, bytes=0, attempted_write_value=None, pc=None,
                CPU_MMIO_instruction_executed=False,
                received_bytes=received_total,
                process_stopped_before_unknown_byte_RXNE_BTF_or_DR_data=True,
                process_stopped_before_RXNE_receive_BTF_or_DR_data=received_total == 0,
                input_level_source=("MAX candidate: pre-write OTP or current register unprovided"
                    if device.startswith("MAX") else
                    "explicit digital pin hypothesis; current register unimplemented"
                    if args.pcal_pin_levels is not None else
                    "unprovided external pins, documented reset default undefined"))
        request_path = directory / "unprovided-I2C-request.json"
        if request_path.exists():
            request = json.loads(request_path.read_text())
            report["unprovided_I2C_request"] = request
            report["unprovided_I2C_request_path"] = str(request_path)
            report["first_unmodeled"] = dict(operation="device_address_response",
                device=None, address7=hex(request["address7"]),
                address=request["mmio_address"], bytes=request["mmio_bytes"],
                attempted_write_value=hex(request["address_byte"]), pc=request["pc"],
                response=None, process_stopped_before_ACK_or_NACK=True,
                register_pointer=None, payload_bytes=[])
        report['modeled_RCC_accesses'] = log_events['modeled_RCC_accesses']
        report['modeled_PWR_control_accesses'] = log_events['modeled_PWR_control_accesses']
        report['modeled_clock_and_FLASH_access_samples'] = log_events['modeled_clock_and_FLASH_access_samples']
        report['FLASH_controller_events'] = log_events['FLASH_controller_events']
        report["FLASH_event_counts"] = complete_log["flash_counts"]
        report['clock_state_transition_events'] = log_events['clock_state_transition_events']
        report['TIM5_TIM11_old_rate_synchronization_events'] = log_events['TIM5_TIM11_old_rate_synchronization_events']
        report['original_deep_sleep_request_boundary_events'] = log_events['original_deep_sleep_request_boundary_events']
        report['host_debug_clock_idle_and_warp_audit'] = log_events['host_debug_clock_idle_and_warp_audit']
        report['TIM5_native_access_samples'] = log_events['TIM5_native_access_samples']
        report['TIM11_native_access_samples'] = log_events['TIM11_native_access_samples']
        report['TIM12_native_access_samples'] = log_events['TIM12_native_access_samples']
        report['TIM8_shared_IRQ43_reset_idle_accesses'] = log_events['TIM8_shared_IRQ43_reset_idle_accesses']
        report['TIM1_shared_IRQ_reset_idle_accesses'] = log_events['TIM1_shared_IRQ_reset_idle_accesses']
        report['GPIO_control_accesses'] = log_events['GPIO_control_accesses']
        report['GPIO_declared_static_pin_profiles_and_original_IDR_reads'] = log_events['GPIO_declared_static_pin_profiles_and_original_IDR_reads']
        report["GPIO_board_input_levels_supplied"] = any(line.startswith("EX1850_GPIO_INPUT ")
            for line in report["GPIO_declared_static_pin_profiles_and_original_IDR_reads"])
        report['SYSCFG_EXTICR_control_accesses'] = log_events['SYSCFG_EXTICR_control_accesses']
        report['EXTI_pending_and_edge_clear_accesses'] = log_events['EXTI_pending_and_edge_clear_accesses']
        spi2_dma_present = all(name in manifest.get("native_mcu_model_headers", {})
            for name in ("ex1850-spi2-dma-core.h", "ex1850-spi2-dma-board.h"))
        report["APB1_SPI_disabled_control_model"] = dict(
            SPI2_base=None if spi2_dma_present else "0x40003800",
            SPI3_base="0x40003c00", APB1_gate_reset_bits=[15] if spi2_dma_present else [14, 15],
            registers=["CR1", "CR2", "I2SCFGR"], status_data_or_activation_supplied=False,
            SPI1_SPI4_wire_or_DMA_modified=False)
        report["SPI2_DMA1_model"] = dict(
            present_in_selected_build=spi2_dma_present,
            selected_model_headers={name: manifest.get("native_mcu_model_headers", {}).get(name)
                for name in ("ex1850-spi2-dma-core.h", "ex1850-spi2-dma-board.h")},
            active_scope="DMA1 Stream4 Channel0, normal/direct 8-bit memory-to-SPI2" if spi2_dma_present else None,
            MOSI_source="original guest SRAM at configured M0AR" if spi2_dma_present else None,
            MISO_source="unknown token; only verified discarded DR read may proceed" if spi2_dma_present else None,
            modeled_status=["TXE", "BSY", "RXNE", "OVR", "HTIF", "TCIF"] if spi2_dma_present else [],
            modeled_interrupts=[15, 36] if spi2_dma_present else [],
            original_guest_callbacks_or_RTOS_flags_written_by_model=False,
            timing_hypotheses=({"DMA_request_HCLK_cycles": 1, "buffer_to_shift_PCLK_cycles": 1,
                "serial_frame_PCLK_cycles": "8 * (2 << BR)",
                "odd_HT_accept_count": "ceil(initial_count / 2); silicon rounding unverified"}
                if spi2_dma_present else None))
        report['SPI2_DMA1_events'] = log_events['SPI2_DMA1_events']
        report['APB1_SPI_disabled_control_events'] = log_events['APB1_SPI_disabled_control_events']
        report['APB1_SPI_strict_boundary_events'] = log_events['APB1_SPI_strict_boundary_events']
        report['APB1RSTR_control_and_I2C_reset_events'] = log_events['APB1RSTR_control_and_I2C_reset_events']
        report['RTC_write_protection_accesses'] = log_events['RTC_write_protection_accesses']
        report['RTC_status_and_clock_events'] = log_events['RTC_status_and_clock_events']
        report['RTC_alarm_control_and_completion_events'] = log_events['RTC_alarm_control_and_completion_events']
        report['RTC_EXTI17_and_IRQ41_events'] = log_events['RTC_EXTI17_and_IRQ41_events']
        report['I2C_controller_configuration_accesses'] = log_events['I2C_controller_configuration_accesses']
        report['I2C2_controller_configuration_accesses'] = log_events['I2C2_controller_configuration_accesses']
        report['DMA1_configuration_status_and_flag_clear_accesses'] = log_events['DMA1_configuration_status_and_flag_clear_accesses']
        report['ADC1_native_configuration_and_conversion_boundary'] = log_events['ADC1_native_configuration_and_conversion_boundary']
        report["ADC1_analog_input_or_conversion_EOC_supplied"] = any(
            line.startswith("EX1850_ADC_CONVERSION_EVENT ") for line in report["ADC1_native_configuration_and_conversion_boundary"])
        report['I2C_bus_status_and_clocked_events'] = log_events['I2C_bus_status_and_clocked_events']
        report['external_device_input_boundary_events'] = log_events['external_device_input_boundary_events']
        report['I2C_received_byte_events_and_original_DR_reads'] = log_events['I2C_received_byte_events_and_original_DR_reads']
        report['I2C_transmit_slots_and_PCAL_register_writes'] = log_events['I2C_transmit_slots_and_PCAL_register_writes']
        report['MAX77711_original_written_register_events'] = log_events['MAX77711_original_written_register_events']
        report['MAX77711_clocked_readback_events'] = log_events['MAX77711_clocked_readback_events']
        report['explicit_external_pin_profile_lines'] = log_events['explicit_external_pin_profile_lines']
        report["I2C_external_input_data_supplied"] = any(line.startswith("EX1850_I2C_RECEIVE_EVENT ")
            for line in report["I2C_received_byte_events_and_original_DR_reads"])
        report["I2C_device_protocol_ACK_supplied"] = any("ACK=1" in line for line in report["I2C_bus_status_and_clocked_events"])
        report["I2C_device_ACK_or_external_data_supplied"] = bool(
            report["I2C_device_protocol_ACK_supplied"] or report["I2C_external_input_data_supplied"])
        report["I2C_device_protocol_ACK_source"] = (
            "explicit per-device PCAL6524 power/RESET/strap or MAX77711 VIO/PHCFG hypothesis"
            if report["I2C_device_protocol_ACK_supplied"] else None)
        report['boundary_hardware_state_lines'] = log_events['boundary_hardware_state_lines']
        report['boundary_CPU_register_observation_lines'] = log_events['boundary_CPU_register_observation_lines']
        report['original_NVIC_reset_write_and_shutdown_trace'] = log_events['original_NVIC_reset_write_and_shutdown_trace']
        captured = directory / "boundary-SRAM.bin"
        if captured.exists():
            raw = captured.read_bytes()
            assert len(raw) == RAM_SIZE
            import struct
            report["boundary_SRAM_snapshot"] = dict(path=str(captured),
                bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest(),
                supplied_to_any_guest=False,
                software_HCLK_word=struct.unpack_from("<I", raw, 0x37FF0)[0],
                HAL_tick_word=struct.unpack_from("<I", raw, 0x20400)[0],
                RTOS_tick_words=list(struct.unpack_from("<2I", raw, 0x22D58)),
                global_start_event_2000F570=raw[0xF570:0xF570+64].hex(),
                service0F_root_20014038=raw[0x14038:0x14038+0xF0].hex(),
                TIM5_handle_2000F534=raw[0xF534:0xF534+64].hex(),
                RTC_handle_20017F68=raw[0x17F68:0x17F68+64].hex())
            report["boundary_SRAM_snapshot"]["I2C1_handle_2001FEA0"] = raw[0x1FEA0:0x1FEA0+96].hex()
            report["boundary_SRAM_snapshot"]["I2C1_ErrorCode"] = struct.unpack_from("<I", raw, 0x1FEA0 + 0x40)[0]
            report["boundary_SRAM_snapshot"]["I2C1_state_byte"] = raw[0x1FEA0 + 0x3D]
            report["boundary_SRAM_snapshot"]["I2C1_root_completion_word"] = struct.unpack_from("<I", raw, 0x1FE94 + 8)[0]
            assert report["boundary_hardware_state_lines"]
            boundary_line = report["boundary_hardware_state_lines"][0]
            assert "original_ROM_sha256=" + EXPECTED_SHA in boundary_line
            report["boundary_input_ROM_identity_log_matches"] = True
            report["original_ROM_at_boundary_still_verified"] = None
        captured_flash = directory / "boundary-simulated-FLASH.bin"
        if captured_flash.exists():
            raw_flash = captured_flash.read_bytes()
            assert len(raw_flash) == len(source)
            flash_sha = hashlib.sha256(raw_flash).hexdigest()
            assert report["boundary_hardware_state_lines"]
            assert "current_simulated_FLASH_sha256=" + flash_sha in report["boundary_hardware_state_lines"][0]
            snapshot = dict(path=str(captured_flash), bytes=len(raw_flash), sha256=flash_sha,
                phase="boundary", captured=True, matches_original_input=raw_flash == source,
                supplied_to_any_guest=False, capture_is_read_only_not_save_or_boot_acceptance=True)
            report["boundary_simulated_FLASH_snapshot"] = snapshot
            report["current_simulated_FLASH_snapshot"] = snapshot
            report["original_ROM_at_boundary_still_verified"] = raw_flash == source
        report["FLASH_source_input_file_final_sha256"] = hashlib.sha256(INPUT.read_bytes()).hexdigest()
        report["FLASH_source_input_file_unchanged"] = report["FLASH_source_input_file_final_sha256"] == EXPECTED_SHA
        assert report["FLASH_source_input_file_unchanged"], "original input file changed during the experiment"
        report["owned_QEMU_exited"] = process is not None and process.poll() is not None
        report["QEMU_exit_code"] = process.returncode if process is not None else None
        report["QEMU_process_lifecycle"] = process_ledger.closed(process)
        report["legacy_field_scopes"] = {
            "owned_QEMU_exited": "this one process terminated; no MCU or camera success",
            "instruction_bytes_modified": "host instruction patching only; guest Flash stores separately recorded",
            "original_ROM_in_memory_verified": "initial simulated Flash before first guest instruction only",
            "original_ROM_at_boundary_still_verified": "actual boundary-array snapshot equality, or null without a snapshot; the input identity log is insufficient"}
        report["EXPEED_manifest_unchanged"] = protected_path.read_bytes() == protected_bytes
        report["EXPEED_binary_identity_unchanged"] = hashlib.sha256(protected_binary.read_bytes()).hexdigest() == protected["binary_sha256"]
        report["boundary_probe_passed"] = bool(not report.get("error") and
            report["original_ROM_in_memory_verified"] and report["CPU_reset_SP_PC_verified"] and
            report["first_unmodeled"] and report["QEMU_exit_code"] == 66 and
            report["owned_QEMU_exited"] and report["EXPEED_manifest_unchanged"] and
            report["EXPEED_binary_identity_unchanged"])
        report["absent_HSE_wait_control_passed"] = bool(args.without_hse and
            not report.get("error") and report.get("budget_reached") and
            report["first_unmodeled"] is None and not report["observations"] and
            not report["clock_state_transition_events"] and
            report["original_ROM_in_memory_verified"] and report["CPU_reset_SP_PC_verified"] and
            report["owned_QEMU_exited"] and report["EXPEED_manifest_unchanged"] and
            report["EXPEED_binary_identity_unchanged"])
        if report["absent_HSE_wait_control_passed"]:
            pc = int(report["budget_stop_registers"]["r15"], 16)
            report["absent_HSE_wait_control_passed"] = bool(
                (0x08000C24 <= pc <= 0x08000C32 or 0x08000644 <= pc <= 0x08000648) and
                report["budget_stop_RAM_tick_word"] == "00000000" and
                report["budget_stop_module_getter_table_prefix"] == "0" * 32)
        report["absent_LSE_native_timeout_reset_control_passed"] = bool(
            args.without_lse and not report.get("error") and not report.get("budget_reached") and
            report["first_unmodeled"] is None and report["QEMU_exit_code"] == 0 and
            report.get("original_pre_SYSRESETREQ_snapshot") and
            any(v.get("native_LSE_timeout_tick_delta", 0) > 5000 for v in report["observations"]) and
            not any("LSE_stable=1" in line for line in report["clock_state_transition_events"]) and
            not report["RTC_status_and_clock_events"] and
            any((int(m[1], 16) & 0xffff0004) == 0x05fa0004
                for line in report["original_NVIC_reset_write_and_shutdown_trace"]
                if (m := re.search(r"nvic_sysreg_write .*addr 0xd0c data 0x([0-9a-f]+)", line))) and
            report["owned_QEMU_exited"] and report["EXPEED_manifest_unchanged"] and
            report["EXPEED_binary_identity_unchanged"])
        report["absent_I2C_slave_native_NACK_control_passed"] = bool(
            report["boundary_probe_passed"] and args.i2c_bus == "released" and args.i2c_slave == "absent" and
            any("ACK=0 AF=1 reason=explicit_absent_slave" in line for line in report["I2C_bus_status_and_clocked_events"]) and
            any("STOP_complete BUSY=0" in line for line in report["I2C_bus_status_and_clocked_events"]) and
            any(int(o["address"], 16) == 0x0802FCBC and
                (int(o["registers"]["cpsr"], 16) & 0x1ff) == 48 for o in report["observations"]) and
            any(int(o["address"], 16) == 0x0802FCD6 and o["registers"]["r1"] == "0x00000002" and
                int.from_bytes(bytes.fromhex(o["original_I2C_driver_root_and_handle"])[0x4C:0x50], "little") == 4
                for o in report["observations"]))
        report["held_low_I2C_SDA_native_BUSY_control_passed"] = bool(
            report["boundary_probe_passed"] and args.i2c_bus == "sda-low" and
            any("value=00000002" in line for line in report["I2C_bus_status_and_clocked_events"]) and
            not any("EX1850_I2C_EVENT " in line for line in report["I2C_bus_status_and_clocked_events"]) and
            any(int(o["address"], 16) == 0x0804469A and o["registers"]["r0"] == "0x00000001"
                and int.from_bytes(bytes.fromhex(o["original_I2C_driver_root_and_handle"])[0x4C:0x50], "little") == 0x20
                for o in report["observations"]))
        report["native_I2C_address_pointer_and_repeated_START_chain_reached"] = bool(
            report["boundary_probe_passed"] and args.i2c_slave == "pcal6524" and
            report["first_unmodeled"].get("operation") == "device_receive_event" and
            any("requested_byte=44" in line for line in report["I2C_bus_status_and_clocked_events"]) and
            any("EX1850_I2C_POINTER W byte=00" in line for line in report["I2C_bus_status_and_clocked_events"]) and
            any("pointer_shift_complete pointer=00 ACK=1" in line for line in report["I2C_bus_status_and_clocked_events"]) and
            any("START_complete SB=1 MSL=1 BUSY=1 repeated=1" in line for line in report["I2C_bus_status_and_clocked_events"]) and
            any("address_shift_complete address_byte=45 address7=22 ACK=1" in line
                for line in report["I2C_bus_status_and_clocked_events"]) and
            report["boundary_SRAM_snapshot"]["I2C1_ErrorCode"] == 0 and
            report["boundary_SRAM_snapshot"]["I2C1_state_byte"] == 0x22 and
            report["boundary_SRAM_snapshot"]["I2C1_root_completion_word"] == 0)
        report["native_first_I2C_read_wrapper_success_under_pin_hypothesis_observed"] = bool(
            args.pcal_pin_levels is not None and report["I2C_external_input_data_supplied"] and
            any(int(o["address"], 16) == 0x08030098 and o["registers"]["r0"] == "0x00000001"
                for o in report["observations"]))
        report["native_ioexp_all_register_setup_return_observed"] = any(
            int(o["address"], 16) == 0x0803016A for o in report["observations"])
        report["native_KEY_completion_callback_load_observed"] = any(
            int(o["address"], 16) == 0x08037EA8 for o in report["observations"])
        report["native_TIM11_irq_callback_flag1_request_observed"] = any(
            int(o["address"], 16) == 0x08038FB4 and o["registers"]["r0"] == "0x2001f374" and
            o["registers"]["r1"] == "0x00000001" for o in report["observations"])
        report["functional_FLASH_budget_observation_passed"] = bool(
            args.flash_mode == "functional" and not report.get("error") and
            report.get("budget_reached") and report["CPU_reset_SP_PC_verified"] and
            report["original_ROM_in_memory_verified"] and report["FLASH_source_input_file_unchanged"] and
            report["owned_QEMU_exited"] and report["EXPEED_manifest_unchanged"] and
            report["EXPEED_binary_identity_unchanged"])
        (directory / "结果.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n")
        print(json.dumps(dict(output=str(directory), boundary_probe_passed=report["boundary_probe_passed"],
            absent_HSE_wait_control_passed=report["absent_HSE_wait_control_passed"],
            absent_LSE_native_timeout_reset_control_passed=report["absent_LSE_native_timeout_reset_control_passed"],
            absent_I2C_slave_native_NACK_control_passed=report["absent_I2C_slave_native_NACK_control_passed"],
            held_low_I2C_SDA_native_BUSY_control_passed=report["held_low_I2C_SDA_native_BUSY_control_passed"],
            native_I2C_address_pointer_and_repeated_START_chain_reached=report["native_I2C_address_pointer_and_repeated_START_chain_reached"],
            native_first_I2C_read_wrapper_success_under_pin_hypothesis_observed=report["native_first_I2C_read_wrapper_success_under_pin_hypothesis_observed"],
            native_ioexp_all_register_setup_return_observed=report["native_ioexp_all_register_setup_return_observed"],
            native_TIM11_irq_callback_flag1_request_observed=report["native_TIM11_irq_callback_flag1_request_observed"],
            error=report.get("error"), first_unmodeled=report["first_unmodeled"],
            observations=len(report["observations"]), modeled_RCC_access_count=len(report["modeled_RCC_accesses"]),
            clock_state_transition_events=report["clock_state_transition_events"],
            owned_QEMU_exited=report["owned_QEMU_exited"], QEMU_exit_code=report["QEMU_exit_code"]), ensure_ascii=False), flush=True)
    if not (report["boundary_probe_passed"] or report["functional_FLASH_budget_observation_passed"] or report["absent_HSE_wait_control_passed"] or
            report["absent_LSE_native_timeout_reset_control_passed"]):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
