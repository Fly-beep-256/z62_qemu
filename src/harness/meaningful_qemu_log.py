"""Drain QEMU output before disk writes; retain bounded events and fault context.

The pipe is always drained, including after either retention budget is spent.
Counts describe emitted input and retained samples separately. This module
changes host logging only; it does not alter guest timing or device semantics.
"""
from collections import Counter, deque
import hashlib
import json
import os
from pathlib import Path
import re
import threading


_TOKEN = re.compile(r"\b((?:EX1850|Z6II)_[A-Z0-9_]+|nvic_sysreg_write|qemu_system_shutdown_request)\b")
_FAULT = re.compile(
    r"UNMODELED|WIRE_BOUNDARY|EX1850_BOUNDARY(?:_|\s)|"
    r"(?:assertion|assert|fatal|panic|Traceback|Error|ERROR|ENOSPC)|"
    r"exception[^\n]*(?:[Aa]bort|[Uu]ndefined|[Hh]ard[Ff]ault)|"
    r"\b(?:IFSR|DFSR|fault_addr)=[1-9a-fA-F]", re.ASCII)
_VOLATILE = re.compile(
    r"\b(?:ns|virtual_ns|now_ns|timestamp|sampled_access_index|index|frame|"
    r"total_received|elapsed_ns|count|hits)=\S+\s*")
_PERIODIC = re.compile(r"TIM10|ICOUNT_(?:IDLE|WARP)|nvic_sysreg_write")
_ACCESS = re.compile(r"(?:_R|_W|_CONTROL|_STATUS|_INPUT|_RECEIVE_DR|_TRANSMIT_DR)$")


class MeaningfulQemuLog:
    """A Popen stdout target with 3 MiB samples plus 1 MiB fault reserve.

    close() must follow termination/wait of the producing process. QEMU's
    optional direct trace writers can use /dev/fd/1 or /dev/fd/2, which feed
    this same bounded sink instead of creating unlimited files.
    """
    def __init__(self, path, *, regular_bytes=3 * 1024 * 1024,
                 fault_bytes=1024 * 1024, max_line_bytes=64 * 1024):
        if regular_bytes < 0 or fault_bytes < 0 or max_line_bytes < 256:
            raise ValueError("invalid log retention budgets")
        self.path = Path(path)
        self.summary_path = self.path.with_name(self.path.stem + "-retention.json")
        self.regular_limit, self.fault_limit = regular_bytes, fault_bytes
        self.max_line_bytes = max_line_bytes
        self.input_lines = self.input_bytes = self.retained_lines = 0
        self.regular_written = self.fault_written = self.file_bytes = 0
        self.discarded = Counter()
        self.input_tokens, self.retained_tokens = Counter(), Counter()
        self.duplicates = Counter()
        self.tail = deque(maxlen=12)
        self.context_remaining = 0
        self.truncated_lines = 0
        self.error = None
        self.closed = False
        self._digest = hashlib.sha256()
        self._output = self.path.open("xb")
        self._read_fd, self._write_fd = os.pipe()
        self._thread = threading.Thread(target=self._drain, name="bounded-qemu-log", daemon=True)
        self._thread.start()

    def fileno(self):
        if self.closed:
            raise ValueError("closed QEMU log")
        return self._write_fd

    def _write(self, raw, *, fault=False):
        used, limit = ((self.fault_written, self.fault_limit) if fault else
                       (self.regular_written, self.regular_limit))
        if used + len(raw) > limit:
            self.discarded["fault_budget" if fault else "regular_budget"] += 1
            return False
        try:
            self._output.write(raw)
        except OSError as exc:
            self.error = f"{type(exc).__name__}: {exc}"
            self.discarded["write_error"] += 1
            return False
        self.file_bytes += len(raw)
        self._digest.update(raw)
        self.retained_lines += 1
        if fault:
            self.fault_written += len(raw)
        else:
            self.regular_written += len(raw)
        return True

    def _line(self, raw):
        text = raw.decode("utf-8", errors="replace")
        match = _TOKEN.search(text[:512])
        token = match[1] if match else "unclassified"
        if token not in self.input_tokens and len(self.input_tokens) >= 512:
            token = "other"
        self.input_tokens[token] += 1
        # Producer totals and the first 512 samples of these diagnostic
        # kinds must survive ordinary-sample budget exhaustion. Backup
        # writes can occur late in shutdown: losing them hides whether the
        # device accepted the original store. Keep backup/reset provenance
        # and the existing UART timeline in the same bounded reserve, with
        # no change to device execution or fault classification.
        diagnostic = token in ("EX1850_USART1_RX_TIMING", "EX1850_USART1_RX_READ",
                               "EX1850_RTC_BACKUP", "EX1850_RTC_BACKUP_RESET",
                               "EX1850_RTC_RETAINED", "EX1850_RCC_BDCR")
        if token in ("EX1850_LOG_SUMMARY", "EX1850_LOG_POLICY") or diagnostic:
            if diagnostic and self.retained_tokens[token] >= 512:
                self.discarded["diagnostic_event_kind_limit"] += 1
                return
            if self._write(raw, fault=True):
                self.retained_tokens[token] += 1
            return
        fault = bool(_FAULT.search(text))
        if fault:
            # Recover the immediately preceding transaction even when its
            # ordinary samples have already exhausted their disk budget.
            for preceding, preceding_token, already_retained in self.tail:
                if self._write(preceding, fault=True) and not already_retained:
                    self.retained_tokens[preceding_token] += 1
            self.tail.clear()
            self.context_remaining = 48  # both Cortex-A cores' register dump
        if fault or self.context_remaining:
            if self._write(raw, fault=True):
                self.retained_tokens[token] += 1
            if not fault:
                self.context_remaining -= 1
            return
        entry = [raw, token, False]
        self.tail.append(entry)
        if _PERIODIC.search(token):
            limit = 2
        elif _ACCESS.search(token):
            limit = 96
        else:
            limit = 512  # DMA, ADC, display and state events; bounded per kind
        if self.retained_tokens[token] >= limit:
            self.discarded["event_kind_limit"] += 1
            return
        if _ACCESS.search(token) or token == "unclassified":
            key = (token, _VOLATILE.sub("", text)[:384])
            if key not in self.duplicates and len(self.duplicates) >= 4096:
                self.discarded["template_limit"] += 1
                return
            self.duplicates[key] += 1
            if self.duplicates[key] > 2:
                self.discarded["duplicate_access"] += 1
                return
        if self._write(raw):
            self.retained_tokens[token] += 1
            entry[2] = True

    def _drain(self):
        continuing = False
        try:
            with os.fdopen(self._read_fd, "rb", buffering=64 * 1024) as source:
                while True:
                    raw = source.readline(self.max_line_bytes + 1)
                    if not raw:
                        break
                    self.input_bytes += len(raw)
                    if continuing:
                        self.discarded["overlong_continuation_chunks"] += 1
                        continuing = not raw.endswith(b"\n")
                        continue
                    self.input_lines += 1
                    if len(raw) > self.max_line_bytes:
                        self.truncated_lines += 1
                        continuing = not raw.endswith(b"\n")
                        raw = raw[:self.max_line_bytes - 32] + b" [overlong line truncated]\n"
                    self._line(raw)
        except Exception as exc:
            self.error = f"{type(exc).__name__}: {exc}"
        finally:
            try:
                self._output.close()
            except OSError as exc:
                self.error = f"{type(exc).__name__}: {exc}"

    def close(self):
        if self.closed:
            return
        self.closed = True
        os.close(self._write_fd)
        self._thread.join(timeout=10)
        if self._thread.is_alive():
            raise RuntimeError("QEMU log producer still holds its output pipe")
        result = self.summary()
        temporary = self.summary_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
        temporary.replace(self.summary_path)
        if self.error:
            raise RuntimeError("QEMU log retention failed: " + self.error)

    def summary(self):
        return dict(schema="qemu-meaningful-log-retention/1", path=str(self.path),
                    summary_path=str(self.summary_path), policy="events-and-fault-context-v1",
                    complete_raw_log_retained=False,
                    input_lines=self.input_lines, input_bytes=self.input_bytes,
                    retained_lines=self.retained_lines, retained_bytes=self.file_bytes,
                    retained_input_lines=sum(self.retained_tokens.values()),
                    discarded_input_lines=self.input_lines - sum(self.retained_tokens.values()),
                    discarded_reasons=dict(self.discarded),
                    discarded_reason_counts_scope="initial filtering decisions; fault prelude may recover samples",
                    input_event_counts=dict(self.input_tokens),
                    retained_event_sample_counts=dict(self.retained_tokens),
                    regular_budget_bytes=self.regular_limit, fault_reserve_bytes=self.fault_limit,
                    hard_limit_bytes=self.regular_limit + self.fault_limit,
                    budget_exhausted=bool(self.discarded["regular_budget"] or self.discarded["fault_budget"]),
                    truncated_input_lines=self.truncated_lines, sha256=self._digest.hexdigest(),
                    fault_context_may_repeat_preceding_samples=True, error=self.error)
