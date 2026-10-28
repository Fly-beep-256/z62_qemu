"""Opt-in serial negative inputs, driven only by completed public UART TX.

This endpoint is an analyst-created clean byte stream, not a battery capture.
It cannot read the MCU's RAM, RNG, registers, or debugger connection. Its full
reply passes the transport ACK/XOR checks but has a zero authentication
response; the original firmware must reject it. The partial reply exercises
the original receive timeout. Neither mode supplies a successful credential.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import socket
import threading
import time


def xor_bytes(data):
    value = 0
    for byte in data:
        value ^= byte
    return value


class FrameParser:
    """Bounded framing of the original length-prefixed TX byte stream."""
    def __init__(self):
        self.pending = bytearray()
        self.counts = Counter()

    def feed(self, data):
        frames = []
        for byte in data:
            self.pending.append(byte)
            while self.pending:
                if self.pending[0] != 2:
                    self.counts['unframed_bytes'] += 1
                    self.pending.pop(0)
                    continue
                if len(self.pending) < 3:
                    break
                payload_size = self.pending[2]
                if payload_size > 64:
                    self.counts['invalid_lengths'] += 1
                    self.pending.pop(0)
                    continue
                length = payload_size + 4
                if len(self.pending) < length:
                    break
                frame = bytes(self.pending[:length])
                if xor_bytes(frame) != 0:
                    self.counts['checksum_failures'] += 1
                    self.pending.pop(0)
                    continue
                del self.pending[:length]
                self.counts['valid_frames'] += 1
                self.counts[f'command_{frame[1]:02x}'] += 1
                frames.append(frame)
        return frames


def negative_reply(mode, frame):
    if len(frame) != 21 or frame[:3] != bytes.fromhex('020111') or xor_bytes(frame):
        return None
    if mode == 'zero-response':
        reply = bytes.fromhex('020600') + bytes(25) + bytes([4])
        assert len(reply) == 29 and xor_bytes(reply) == 0
        assert not any(reply[11:28])
        return reply
    if mode == 'partial-timeout':
        return bytes.fromhex('020600')
    raise ValueError('unknown synthetic negative mode')


class SerialNegativePeer:
    MODES = ('zero-response', 'partial-timeout')
    MAX_REPLIES = 64
    RAW_LIMIT = 256 * 1024
    EVENT_LIMIT = 64
    # A declared host turnaround policy; not a measured battery latency or
    # an ordering relationship with any guest virtual clock.
    TURNAROUND_SECONDS = 0.002

    def __init__(self, directory, mode, max_replies=3):
        if mode not in self.MODES or not 1 <= max_replies <= self.MAX_REPLIES:
            raise ValueError('explicit endpoint mode and bounded reply count required')
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=False)
        self.mode, self.max_replies = mode, max_replies
        self.parser = FrameParser()
        self.connected = threading.Event()
        self.stopping = threading.Event()
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen(1)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.connection = None
        self.tx_bytes = self.rx_bytes = self.reply_count = 0
        self.events, self.error = [], None
        self.tx_path = self.directory / 'UART1-TX.bin'
        self.rx_path = self.directory / 'UART1-RX.bin'
        self.tx_file = self.tx_path.open('xb')
        self.rx_file = self.rx_path.open('xb')
        self.worker = threading.Thread(target=self._run, name='explicit-usart1-negative-peer', daemon=True)
        self.worker.start()

    @property
    def chardev(self):
        return f'socket,id=ex1850-usart1,host=127.0.0.1,port={self.port},nodelay=on'

    def wait_connected(self, timeout=5):
        if not self.connected.wait(timeout) or self.connection is None:
            raise RuntimeError(self.error or 'USART1 peer did not connect before original guest continue')

    def reply(self, frame):
        return negative_reply(self.mode, frame)

    def event_fields(self, frame, reply):
        return dict(original_authentication_success_supplied=False)

    def result_fields(self):
        return {}

    def _run(self):
        try:
            while not self.stopping.is_set():
                try:
                    self.connection, _ = self.listener.accept()
                    break
                except socket.timeout:
                    pass
            if self.connection is None:
                return
            self.connection.settimeout(0.1)
            self.connected.set()
            while not self.stopping.is_set():
                try:
                    data = self.connection.recv(4096)
                except socket.timeout:
                    continue
                if not data:
                    break
                if self.tx_bytes + len(data) > self.RAW_LIMIT:
                    raise ValueError('USART1 public TX exceeds the declared 256 KiB limit')
                self.tx_file.write(data)
                self.tx_bytes += len(data)
                for frame in self.parser.feed(data):
                    reply = self.reply(frame)
                    if reply is None or self.reply_count >= self.max_replies:
                        continue
                    if self.stopping.wait(self.TURNAROUND_SECONDS):
                        break
                    self.connection.sendall(reply)
                    self.rx_file.write(reply)
                    self.rx_bytes += len(reply)
                    self.reply_count += 1
                    if len(self.events) < self.EVENT_LIMIT:
                        self.events.append(dict(sequence=self.reply_count,
                            public_TX=frame.hex(), synthetic_RX=reply.hex(),
                            host_monotonic_ns=time.monotonic_ns(),
                            mode=self.mode, **self.event_fields(frame, reply)))
        except Exception as error:
            if not self.stopping.is_set():
                self.error = f'{type(error).__name__}: {error}'
                self.connected.set()

    def finish(self):
        self.stopping.set()
        self.worker.join(timeout=1)
        if self.worker.is_alive() and self.connection is not None:
            self.connection.shutdown(socket.SHUT_RDWR)
            self.worker.join(timeout=1)
        if self.worker.is_alive():
            raise RuntimeError('owned USART1 peer did not stop')
        if self.connection is not None:
            self.connection.close()
        self.listener.close()
        self.tx_file.close()
        self.rx_file.close()
        sources = {}
        for name, path in [('public_TX', self.tx_path), ('synthetic_RX', self.rx_path)]:
            raw = path.read_bytes()
            sources[name] = dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        result = dict(schema='ex1850.usart1-explicit-negative-wire-input/1',
            enabled=True, mode=self.mode, connected=self.connected.is_set() and self.connection is not None,
            input_kind='analyst-created synthetic clean asynchronous authentication negative',
            original_battery_capture=False, private_RAM_RNG_or_register_access=False,
            guest_RAM_or_register_writes=False, authentication_success_supplied=False,
            response_is_function_of_public_TX_only=True,
            host_turnaround_seconds=self.TURNAROUND_SECONDS,
            physical_turnaround_or_guest_clock_ordering_verified=False,
            max_replies=self.max_replies, replies=self.reply_count,
            public_TX_bytes=self.tx_bytes, synthetic_RX_bytes=self.rx_bytes,
            parser_counts=dict(self.parser.counts), partial_TX_tail=self.parser.pending.hex(),
            event_limit=self.EVENT_LIMIT, events=self.events,
            raw_limit_per_direction=self.RAW_LIMIT, streams=sources,
            worker_stopped=True, error=self.error)
        result.update(self.result_fields())
        path = self.directory / 'closed.json'
        path.write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
        return result
