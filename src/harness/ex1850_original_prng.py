"""Pure reconstruction of the original Z6II 1.70 MCU srand/rand/nonce path.

Source: original MCU SHA256
4314c17d9a6676a4254aa4d74d4aa35411e3a793ea7056c06f9c83f160da3cb1.
08020468..08020490 seeds the 55-word table; 080200EC..0802011A
updates it; 08042602..0804261C stores eight low halfwords and a zero
halfword. A successful 08044C68 call supplies one hardware RNG DR word.

This module reads no file, guest state, retained SRAM, camera or debugger.
Its input word is a caller-supplied public synthetic entropy parameter.
It does not establish a physical battery private key or factory entropy.
"""

WORD_MASK = 0xFFFFFFFF
RESULT_MASK = 0x7FFFFFFF
TABLE_WORDS = 55
LCG_MULTIPLIER = 69069
LCG_INCREMENT = 0x66D619E1


class OriginalPRNG:
    """Exact u32 state and pointer order of original srand/rand functions."""

    def __init__(self, rng_word):
        if type(rng_word) is not int or not 0 <= rng_word <= WORD_MASK:
            raise ValueError('RNG word must be an unsigned 32-bit integer')
        state = [0] * TABLE_WORDS
        value = rng_word
        for index in range(TABLE_WORDS - 1, -1, -1):
            state[index] = (value + (value >> 16)) & WORD_MASK
            value = (value * LCG_MULTIPLIER + LCG_INCREMENT) & WORD_MASK
        self.state = state
        self.left = 31
        self.right = 0

    def next31(self):
        value = (self.state[self.left] + self.state[self.right]) & WORD_MASK
        self.state[self.right] = value
        self.left = (self.left + 1) % TABLE_WORDS
        self.right = (self.right + 1) % TABLE_WORDS
        return value & RESULT_MASK

    def nonce18(self):
        return b''.join((self.next31() & 0xFFFF).to_bytes(2, 'little')
                        for _ in range(8)) + b'\x00\x00'


def rng_word_to_nonce18(rng_word):
    """First nonce after one successful DR read and original srand(word)."""
    return OriginalPRNG(rng_word).nonce18()


def auth_tag8_from_public_entropy(constants, rng_word, public_tx21, response17):
    """Recompute tag from public entropy only after the natural TX C matches.

    The caller must provide the immutable original-ROM constants through
    inspect_public_auth_tx.load_original_rom, and a sourced canonical,
    nonzero 17-byte response parameter. A saved nonce, C, H, RX29 or guest
    state is neither accepted nor read. Returns tag8 only; wire framing and
    public synthetic entropy transport are the caller's responsibilities.
    """
    from ex1850_public_auth_math import OriginalField, parse_public_auth_tx

    if rng_word == 0:
        raise ValueError('public functional RNG profile requires a nonzero DR word')
    if not isinstance(response17, bytes) or len(response17) != 17:
        raise ValueError('response must be exactly 17 bytes')
    response = int.from_bytes(response17, 'little')
    if not 0 < response < (1 << 131):
        raise ValueError('response must be a canonical nonzero field element')
    tx = parse_public_auth_tx(public_tx21)
    value = lambda name: int.from_bytes(
        bytes.fromhex(constants[name]['little_endian_hex']), 'little')
    field = OriginalField(value('modulus'), value('sqrt_b'))
    nonce = int.from_bytes(rng_word_to_nonce18(rng_word), 'little')
    calculated_c = field.ladder(value('G_x'), nonce).to_bytes(18, 'little')
    if calculated_c[:17].hex() != tx['C_17_bytes']:
        raise ValueError('natural public TX C does not match the public entropy contract')
    calculated_h = field.ladder(value('P_x'), nonce)
    return field.mul(calculated_h, response).to_bytes(18, 'little')[:8]
