import socket
import struct
import random
import time
import select

NETAT_BUFF_SIZE = 1024
NETAT_PORT = 56789

WNB_NETAT_CMD_SCAN_REQ = 1
WNB_NETAT_CMD_SCAN_RESP = 2
WNB_NETAT_CMD_AT_REQ = 3
WNB_NETAT_CMD_AT_RESP = 4

MAC2STR = lambda a: (a[0] & 0xff, a[1] & 0xff, a[2] & 0xff, a[3] & 0xff, a[4] & 0xff, a[5] & 0xff)
MACSTR = "%02x:%02x:%02x:%02x:%02x:%02x"


class WnbNetatCmd:
    def __init__(self):
        self.cmd = 0
        self.len = b'\x00\x00'
        self.dest = b'\x00\x00\x00\x00\x00\x00'
        self.src = b'\x00\x00\x00\x00\x00\x00'
        self.data = b''


class NetatMgr:
    def __init__(self):
        self.sock = 0
        self.dest = b'\xff\xff\xff\xff\xff\xff'
        self.cookie = b'\x00\x00\x00\x00\x00\x00'
        self.recvbuf = bytearray(NETAT_BUFF_SIZE)


libnetat = NetatMgr()


def random_bytes(length):
    return bytes([random.randint(0, 255) for _ in range(length)])


def sock_send(sock, data):
    dest = ('<broadcast>', NETAT_PORT)
    return sock.sendto(data, dest)


def sock_recv(sock, timeout):
    rlist, _, _ = select.select([sock], [], [], timeout)
    if sock in rlist:
        return sock.recvfrom(NETAT_BUFF_SIZE)
    return None, None


def netat_scan():
    global libnetat
    scan = WnbNetatCmd()
    libnetat.cookie = random_bytes(6)
    scan.cmd = WNB_NETAT_CMD_SCAN_REQ
    scan.dest = b'\xff\xff\xff\xff\xff\xff'
    scan.src = libnetat.cookie
    sock_send(libnetat.sock, scan.__bytes__())


def netat_send(atcmd):
    global libnetat
    cmd = WnbNetatCmd()
    libnetat.cookie = random_bytes(6)
    cmd.cmd = WNB_NETAT_CMD_AT_REQ
    cmd.len = struct.pack('>H', len(atcmd))
    cmd.dest = libnetat.dest
    cmd.src = libnetat.cookie
    cmd.data = atcmd.encode('utf-8')
    sock_send(libnetat.sock, cmd.__bytes__())


def netat_recv(buff, timeout):
    global libnetat
    off = 0
    cmd = WnbNetatCmd()

    while True:
        data, _ = sock_recv(libnetat.sock, timeout)
        if data:
            cmd_len = len(data)
            if cmd_len >= 14:
                cmd_bytes = bytearray(data)
                cmd.cmd = cmd_bytes[0]
                cmd.len = cmd_bytes[1:3]
                cmd.dest = cmd_bytes[3:9]
                cmd.src = cmd_bytes[9:15]
                cmd.data = cmd_bytes[15:]

                if cmd.dest == libnetat.cookie:
                    if cmd.cmd == WNB_NETAT_CMD_SCAN_RESP:
                        libnetat.dest = cmd.src
                    elif cmd.cmd == WNB_NETAT_CMD_AT_RESP:
                        if buff:
                            buff[off:off + len(cmd.data)] = cmd.data
                            off += len(cmd.data)
                        else:
                            print(cmd.data.decode('utf-8'))
            else:
                break
        else:
            break

    if buff:
        buff[off] = 0


def libnetat_init(ifname):
    global libnetat
    on = 1
    libnetat.dest = b'\xff\xff\xff\xff\xff\xff'
    libnetat.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    libnetat.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, on)

    try:
        libnetat.sock.bind(('0.0.0.0', NETAT_PORT))
        req = struct.pack('16s', ifname.encode('utf-8'))
        libnetat.sock.setsockopt(socket.SOL_SOCKET, 25, req)
    except Exception as e:
        print(f"Error binding socket: {e}")
        libnetat.sock.close()
        return -1

    netat_scan()
    netat_recv(None, 1)
    return 0


def libnetat_send(atcmd):
    global libnetat
    if libnetat.sock == 0:
        print("libnetat is not initialized!")
        return -1

    if libnetat.dest[0] & 0x1:
        netat_scan()
        netat_recv(None, 100)

    if libnetat.dest[0] & 0x1:
        print("Device not detected!")
        return -1

    response_buff = bytearray(1024)
    netat_send(atcmd)
    return netat_recv(response_buff, 10)


if __name__ == "__main__":
    import sys

    if len(sys.argv) == 2:
        ifname = sys.argv[1]
    else:
        print("Please input the interface name!")
        sys.exit(-1)

    if libnetat_init(ifname):
        print(f"libnetat init failed, interface: {ifname}")
        sys.exit(-1)

    while True:
        input_cmd = input("\n>: ")
        if input_cmd and (input_cmd.startswith("at") or input_cmd.startswith("AT")):
            response_buff = bytearray(1024)
            libnetat_send(input_cmd, response_buff, 1024)
            print(response_buff.decode('utf-8'))
