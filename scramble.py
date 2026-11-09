import struct
A0 = 0x07B48238
B0 = 0xE34EAC63
C_A1 = 0xE9FA57E4
C_A2 = 0x8E495673
C_B1 = 0x4F8B1BCA
C_B2 = 0x72F6FCBE
C_W1 = 0xB43B9BAF
C_W2 = 0xAF57F7FB


def e9b0_forward(data: bytes, seed: int) -> bytes:
    out = bytearray(data)
    nwords = len(out) // 4
    s = seed & 0xFFFFFFFF
    a = A0
    b = B0
    for i in range(nwords):
        t = (a + C_A1) & 0xFFFFFFFF
        t = (t * a) & 0xFFFFFFFF
        t = (t + s) & 0xFFFFFFFF
        a = (t + C_A2) & 0xFFFFFFFF
        a = (a << (i & 7)) & 0xFFFFFFFF

        t = (b + C_B1) & 0xFFFFFFFF
        t = (t * b) & 0xFFFFFFFF
        t = (t + s) & 0xFFFFFFFF
        b = (t + C_B2) & 0xFFFFFFFF
        b = (b >> ((i * i) & 0xF)) & 0xFFFFFFFF

        s = (a ^ b) & 0xFFFFFFFF

        off = i * 4
        w = struct.unpack_from("<I", out, off)[0]
        w = (w + (((i & 0xD) * C_W1) & 0xFFFFFFFF)) & 0xFFFFFFFF
        w = (w ^ (((i & 3) * C_W2) & 0xFFFFFFFF)) & 0xFFFFFFFF
        w = (w - s) & 0xFFFFFFFF
        w = (w ^ s) & 0xFFFFFFFF
        struct.pack_into("<I", out, off, w)
    return bytes(out)


