# SPDX-License-Identifier: GPL-2.0-or-later
"""QMP and PNG utilities extracted from the original community harness."""
import socket, struct, zlib, json

def ppm_pixels(data):
    # QEMU's screendump P6 header, followed by packed RGB bytes.
    magic, dimensions, maximum, pixels = data.split(b'\n', 3)
    w, h = map(int, dimensions.split())
    if magic != b'P6' or maximum != b'255' or (w, h) not in ((720, 480), (1024, 682), (1024, 680)) or len(pixels) != w*h*3:
        raise ValueError('Unexpected QEMU screenshot format')
    return w, h, pixels

def rgb_png(w, h, pixels):
    def chunk(kind, payload):
        return struct.pack('>I', len(payload))+kind+payload+struct.pack('>I', zlib.crc32(kind+payload))
    rows = b''.join(b'\0'+pixels[y*w*3:(y+1)*w*3] for y in range(h))
    png = b'\x89PNG\r\n\x1a\n'+chunk(b'IHDR', struct.pack('>IIBBBBB', w, h, 8, 2, 0, 0, 0))
    return png+chunk(b'IDAT', zlib.compress(rows, 1))+chunk(b'IEND', b'')

def ppm_png(data):
    w, h, pixels = ppm_pixels(data)
    return rgb_png(w, h, pixels), pixels

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

class QMP:
    def __init__(self, port):
        self.socket = socket.create_connection(('127.0.0.1', port), 5)
        self.file = self.socket.makefile('rwb', buffering=0)
        json.loads(self.file.readline())
        self.command('qmp_capabilities')

    def command(self, name, arguments=None):
        request = {'execute': name}
        if arguments is not None:
            request['arguments'] = arguments
        self.file.write(json.dumps(request).encode()+b'\n')
        while True:
            raw = self.file.readline()
            if not raw:
                raise EOFError('QEMU monitor disconnected')
            reply = json.loads(raw)
            if 'error' in reply:
                raise RuntimeError(reply['error'])
            if 'return' in reply:
                return reply['return']
            if (name == 'quit' and reply.get('event') == 'SHUTDOWN'
                    and reply.get('data', {}).get('reason') == 'host-qmp-quit'):
                # QEMU may close after the terminal event without a return.
                # The caller still waits for the owned process's actual exit.
                return {'shutdown_event_observed': True}

    def close(self):
        self.file.close()
        self.socket.close()
