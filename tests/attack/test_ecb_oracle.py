from cryptolib.attack.block_cipher import ecb_oracle_attack
from cryptolib.cipher import AES


def test_ecb_oracle():
    KEY = 0x000102030405060708090a0b0c0d0e0f.to_bytes(16, "big")
    PLAIN = b'test{hoge_fuga_foo_bar}'
    aes = AES.new(KEY, AES.MODE_ECB)

    def oracle(plain):
        def pad(x):
            pad_size = len(x) % 16
            return x + bytes([pad_size] * pad_size)
        return aes.encrypt(pad(plain + PLAIN))

    _plain = ecb_oracle_attack(16, oracle)
    assert PLAIN == _plain
