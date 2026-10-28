"""Shepot PNG carrier v1: bounded RGB8 PNG, LSB-packed signed JSON.

This is a transport envelope, not encryption. P-256 validation remains mandatory.
"""
import struct
import zlib

SIGNATURE = b'\x89PNG\r\n\x1a\n'
MAGIC = b'SHPTRGB1'
MAX_JSON = 32768
MAX_IMAGE = 262144
MAX_SIDE = 512


def paeth(a, b, c):
    p = a + b - c
    distances = (abs(p - a), abs(p - b), abs(p - c))
    return (a, b, c)[distances.index(min(distances))]


def chunk(kind, data):
    return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind + data))


def encode(payload, width=512, height=512, filters=(0, 1, 2, 3, 4), split=32768):
    if not 0 < len(payload) <= MAX_JSON or not 0 < width <= MAX_SIDE or not 0 < height <= MAX_SIDE:
        raise ValueError('Invalid carrier dimensions or payload')
    envelope = MAGIC + struct.pack('>I', len(payload)) + payload
    if len(envelope) * 8 > width * height * 3 or not filters or any(f not in range(5) for f in filters) or split < 1:
        raise ValueError('Insufficient carrier capacity')
    pixels = bytearray()
    for y in range(height):
        for x in range(width):
            pixels.extend((16 + x * 20 // width, 28 + y * 36 // height, 48 + (x + y) * 45 // (width + height)))
    for bit in range(len(envelope) * 8):
        pixels[bit] = (pixels[bit] & 254) | ((envelope[bit // 8] >> (7 - bit % 8)) & 1)
    stride = width * 3
    filtered = bytearray()
    for y in range(height):
        mode = filters[y % len(filters)]
        filtered.append(mode)
        for x in range(stride):
            at = y * stride + x
            a = pixels[at - 3] if x >= 3 else 0
            b = pixels[at - stride] if y else 0
            c = pixels[at - stride - 3] if y and x >= 3 else 0
            prediction = (0, a, b, (a + b) // 2, paeth(a, b, c))[mode]
            filtered.append((pixels[at] - prediction) & 255)
    compressed = zlib.compress(filtered, 9)
    image = SIGNATURE + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
    image += b''.join(chunk(b'IDAT', compressed[i:i + split]) for i in range(0, len(compressed), split))
    image += chunk(b'IEND', b'')
    if len(image) > MAX_IMAGE:
        raise ValueError('Carrier exceeds wire limit')
    return image


def decode(image):
    if len(image) > MAX_IMAGE or not image.startswith(SIGNATURE):
        raise ValueError('Invalid PNG carrier')
    offset, width, height, count, state = 8, 0, 0, 0, 0
    compressed = bytearray()
    while offset < len(image):
        count += 1
        if count > 128 or len(image) - offset < 12:
            raise ValueError('Invalid PNG chunks')
        size = struct.unpack_from('>I', image, offset)[0]
        end = offset + size + 12
        if size > MAX_IMAGE or end > len(image):
            raise ValueError('Truncated PNG chunk')
        kind = image[offset + 4:offset + 8]
        data = image[offset + 8:end - 4]
        if zlib.crc32(kind + data) != struct.unpack_from('>I', image, end - 4)[0]:
            raise ValueError('PNG CRC mismatch')
        if kind == b'IHDR' and state == 0 and size == 13:
            width, height, depth, color, compression, filtering, interlace = struct.unpack('>IIBBBBB', data)
            if not 0 < width <= MAX_SIDE or not 0 < height <= MAX_SIDE or (depth, color, compression, filtering, interlace) != (8, 2, 0, 0, 0):
                raise ValueError('Unsupported PNG format')
            state = 1
        elif kind == b'IDAT' and state in (1, 2):
            compressed.extend(data)
            state = 2
        elif kind == b'IEND' and state == 2 and size == 0 and end == len(image):
            state = 3
        else:
            raise ValueError('Unsupported PNG chunk or order')
        offset = end
    if state != 3:
        raise ValueError('Incomplete PNG')
    stride = width * 3
    expected = (stride + 1) * height
    inflater = zlib.decompressobj()
    try:
        raw = inflater.decompress(compressed, expected + 1)
    except zlib.error:
        raise ValueError('Invalid PNG compressed stream') from None
    if len(raw) != expected or not inflater.eof or inflater.unused_data or inflater.unconsumed_tail:
        raise ValueError('Invalid PNG compressed stream')
    pixels = bytearray(stride * height)
    for y in range(height):
        mode = raw[y * (stride + 1)]
        if mode > 4:
            raise ValueError('Invalid PNG filter')
        for x in range(stride):
            at = y * stride + x
            a = pixels[at - 3] if x >= 3 else 0
            b = pixels[at - stride] if y else 0
            c = pixels[at - stride - 3] if y and x >= 3 else 0
            prediction = (0, a, b, (a + b) // 2, paeth(a, b, c))[mode]
            pixels[at] = (raw[y * (stride + 1) + x + 1] + prediction) & 255

    def extract(start, count):
        if (start + count) * 8 > len(pixels):
            raise ValueError('Truncated PNG payload')
        return bytes(sum((pixels[(start + i) * 8 + bit] & 1) << (7 - bit) for bit in range(8)) for i in range(count))

    header = extract(0, 12)
    length = struct.unpack_from('>I', header, 8)[0]
    if header[:8] != MAGIC or not 0 < length <= MAX_JSON:
        raise ValueError('Invalid PNG envelope')
    return extract(12, length)


def directory(data):
    if data.startswith(SIGNATURE):
        return decode(data)
    if not 0 < len(data) <= MAX_JSON:
        raise ValueError('Invalid JSON directory size')
    return data


def self_test():
    import unittest

    class CarrierTests(unittest.TestCase):
        def test_round_trip_all_filters_and_split_idat(self):
            for mode in range(5):
                self.assertEqual(decode(encode(b'{"test":1}', width=16, height=16, filters=(mode,), split=23)), b'{"test":1}')

        def test_crc_and_truncation(self):
            image = encode(b'{}', width=16, height=16)
            corrupt = bytearray(image); corrupt[30] ^= 1
            for bad in (bytes(corrupt), image[:-1], image + b'junk'):
                with self.assertRaises(ValueError): decode(bad)

        def test_limits(self):
            for payload in (b'', b'x' * (MAX_JSON + 1)):
                with self.assertRaises(ValueError): encode(payload)
            with self.assertRaises(ValueError): encode(b'{}', width=1, height=1)
            with self.assertRaises(ValueError): decode(b'x' * (MAX_IMAGE + 1))

        def test_json_compatibility(self):
            self.assertEqual(directory(b'{}'), b'{}')
            self.assertEqual(directory(encode(b'{}', width=16, height=16)), b'{}')

    result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(CarrierTests))
    if not result.wasSuccessful():
        raise SystemExit(1)


if __name__ == '__main__':
    self_test()
