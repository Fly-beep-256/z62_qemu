"""Explicit battery wire input, with public synthetic entropy and sourced fields.

The endpoint receives only public UART TX and an immutable input specification.
It reconstructs the original PRNG from declared external RNG words and accepts
an authentication challenge only when its C matches that reconstruction. It
does not obtain a physical battery private key, read guest state, or publish
READY/power values. The unchanged MCU must verify the reply and own publication.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
from portable_identity import normalize_battery_spec

from ex1850_original_prng import auth_tag8_from_public_entropy, rng_word_to_nonce18
from ex1850_public_auth_math import OriginalField, load_original_rom, parse_public_auth_tx
from ex1850_usart1_peer import SerialNegativePeer, xor_bytes


SCHEMA = 'z6ii.public-entropy-battery-wire-spec/1'
INPUT_KIND = 'public synthetic entropy with sourced battery protocol parameters'


def file_identity(path):
    path = Path(path).resolve(strict=True)
    raw = path.read_bytes()
    return dict(path=str(path), bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())


def load_spec(path):
    path = Path(path).resolve(strict=True)
    spec = json.loads(path.read_text())
    if spec.get('schema') != SCHEMA or spec.get('input_classification') != INPUT_KIND:
        raise ValueError('explicit public entropy battery input classification required')
    if spec.get('physical_battery_private_key_recovered') is not False:
        raise ValueError('public entropy does not establish a physical battery private key')
    spec = normalize_battery_spec(spec)
    for item in [spec['ROM'], *spec['source_evidence']]:
        if file_identity(item['path']) != item:
            raise ValueError('battery input source identity changed: ' + item['path'])
    words = spec['public_entropy']['words']
    if not 1 <= len(words) <= 64 or any(type(w) is not int or not 0 < w < 2**32 for w in words):
        raise ValueError('public entropy must declare 1..64 nonzero u32 words')
    if spec['public_entropy']['classification'] != 'analyst-created synthetic external RNG words':
        raise ValueError('external entropy origin must remain explicit')
    _, constants = load_original_rom(Path(spec['ROM']['path']))
    response = bytes.fromhex(spec['authentication']['response17'])
    if len(response) != 17 or not 0 < int.from_bytes(response, 'little') < 2**131:
        raise ValueError('sourced authentication response must be a canonical nonzero field element')
    source_paths = {x['path'] for x in spec['source_evidence']}
    for transaction in spec['exact_transactions']:
        tx, rx = (bytes.fromhex(transaction[x]) for x in ('TX', 'RX'))
        if len(tx) < 4 or tx[0] != 2 or len(tx) != tx[2] + 4 or xor_bytes(tx):
            raise ValueError('invalid exact original TX contract')
        if len(rx) != transaction['expected_RX_bytes'] or len(rx) < 4 or rx[:2] != b'\x02\x06' or xor_bytes(rx):
            raise ValueError('invalid exact reply contract')
        if transaction['classification'] not in ('retained physical battery TX/RX cache pair', 'ROM-derived synthetic battery reply'):
            raise ValueError('reply classification must distinguish capture and synthesis')
        if not transaction['source_paths'] or not set(transaction['source_paths']) <= source_paths:
            raise ValueError('each reply needs identity-bound source evidence')
    return spec, constants


class BatteryProtocol:
    """No debugger or live guest interface; strict known wire transactions only."""
    def __init__(self, spec, constants):
        self.spec, self.constants = spec, constants
        self.words = list(spec['public_entropy']['words'])
        self.response17 = bytes.fromhex(spec['authentication']['response17'])
        self.exact = {}
        for transaction in spec['exact_transactions']:
            tx = bytes.fromhex(transaction['TX'])
            if tx in self.exact:
                raise ValueError('duplicate exact TX contract')
            self.exact[tx] = transaction
        value = lambda name: int.from_bytes(bytes.fromhex(constants[name]['little_endian_hex']), 'little')
        field = OriginalField(value('modulus'), value('sqrt_b'))
        self.challenges = {}
        self.authentication_tags = {}
        for index, word in enumerate(self.words):
            nonce = int.from_bytes(rng_word_to_nonce18(word), 'little')
            c = field.ladder(value('G_x'), nonce).to_bytes(18, 'little')[:17]
            self.challenges.setdefault(c, []).append(index)
            # All calculations use declared immutable public inputs before
            # the guest starts. Select a tag only after the actual TX C matches;
            # the UART worker must not spend a receive deadline on field math.
            h = field.ladder(value('P_x'), nonce)
            self.authentication_tags[index] = field.mul(
                h, int.from_bytes(self.response17, 'little')).to_bytes(18, 'little')[:8]
        self.counts = Counter()
        self.last_fields = {}
        self.unknown_requests = []

    def reply(self, frame):
        if len(frame) < 4 or frame[0] != 2 or len(frame) != frame[2] + 4 or xor_bytes(frame):
            raise ValueError('invalid completed public TX frame')
        self.counts[f'TX_command_{frame[1]:02x}'] += 1
        if frame[:3] == b'\x02\x01\x11':
            parsed = parse_public_auth_tx(frame)
            candidates = self.challenges.get(frame[3:20])
            if not candidates:
                self.counts['authentication_challenge_mismatches'] += 1
                raise ValueError('natural public TX C does not match any declared external RNG word')
            index = candidates[0]
            tag = self.authentication_tags[index]
            prefix = b'\x02\x06\x00' + tag + self.response17
            rx = prefix + bytes([xor_bytes(prefix)])
            assert len(rx) == 29 and xor_bytes(rx) == 0
            self.counts['authentication_replies'] += 1
            self.last_fields = dict(transaction='authentication_TX21_RX29',
                public_entropy_matching_word_indices=[i + 1 for i in candidates],
                actual_public_C=parsed['C_17_bytes'], tag8_recomputed_for_actual_challenge=True,
                response17_source=self.spec['authentication']['response17_source'],
                reply_classification='synthetic tag for actual challenge with captured nonzero response parameter',
                original_authentication_success_supplied=True,
                native_authentication_result_observed=False)
            return rx
        transaction = self.exact.get(frame)
        if transaction is None:
            self.counts['unmodeled_requests'] += 1
            if len(self.unknown_requests) < 8:
                self.unknown_requests.append(frame.hex())
            raise ValueError('unmodeled battery request ' + frame.hex() + '; no reply guessed')
        if not self.counts['authentication_replies'] and not transaction.get('allowed_before_authentication', False):
            raise ValueError('post-authentication request received before a matching authentication challenge')
        self.counts['ordinary_replies'] += 1
        self.last_fields = dict(transaction=transaction['name'],
            reply_classification=transaction['classification'],
            source_paths=transaction['source_paths'], original_authentication_success_supplied=False,
            native_authentication_result_observed=False)
        return bytes.fromhex(transaction['RX'])


class SerialBatteryPeer(SerialNegativePeer):
    MODES = ('public-entropy-battery',)
    MAX_REPLIES = 8192
    EVENT_LIMIT = 96

    def __init__(self, directory, specification, public_words, max_replies=4096):
        self.specification = file_identity(specification)
        spec, constants = load_spec(specification)
        if list(public_words) != spec['public_entropy']['words']:
            raise ValueError('MCU external RNG words and battery peer public entropy differ')
        self.protocol = BatteryProtocol(spec, constants)
        super().__init__(directory, 'public-entropy-battery', max_replies)

    def reply(self, frame):
        if self.reply_count >= self.max_replies:
            raise ValueError('declared battery reply budget exhausted')
        reply = self.protocol.reply(frame)
        if self.rx_bytes + len(reply) > self.RAW_LIMIT:
            raise ValueError('battery RX exceeds declared raw retention limit')
        return reply

    def event_fields(self, frame, reply):
        return dict(self.protocol.last_fields)

    def result_fields(self):
        return dict(schema='ex1850.public-entropy-battery-wire-input/1',
            input_kind=INPUT_KIND, specification=self.specification,
            original_battery_capture=False,
            physical_battery_private_key_recovered=False,
            captured_battery_parameters_used=True,
            authentication_success_supplied=bool(self.protocol.counts['authentication_replies']),
            authentication_success_scope='Wire credential supplied; unchanged MCU result and power publication require separate cold-run evidence',
            response_is_function_of_public_TX_only=False,
            response_is_function_of_public_TX_and_declared_external_inputs_only=True,
            public_entropy=self.protocol.spec['public_entropy'],
            protocol_counts=dict(self.protocol.counts),
            unmodeled_public_TX=self.protocol.unknown_requests,
            actual_native_power_or_acquisition_success_observed=False)
