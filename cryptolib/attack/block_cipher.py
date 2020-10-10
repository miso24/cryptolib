from typing import Callable

def ecb_oracle_attack(block_size: int, oracle: Callable[[], bytes], block_max: int = 4) -> bytes:
    """
        ECB oracle attack
    """
    payload = b'B' * block_size
    payload += b'A' * block_size * block_max
    found = b''
    idx = 1
    size = block_size * (block_max + 1)
    while True:
        is_finished = True
        target = oracle(payload[:-idx])[:size]
        for i in range(32, 128):
            tmp = payload[:block_size] + payload[block_size+idx:] \
                + found + bytes([i])
            enc = oracle(tmp)[:size]
            if enc == target:
                found += bytes([i])
                is_finished = False
                break
        if is_finished:
            return found
        idx += 1
