import socket
import os
import sys
import struct
import time
import select

"""
ICMP Packet

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type(8)   |     Code(0)   |          Checksum             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           Identifier          |        Sequence Number        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             Payload                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
"""


def checksum(string):
    string = str(string)
    csum = 0
    countTo = (len(string) // 2) * 2

    count = 0
    while count < countTo:
        thisVal = ord(string[count + 1]) * 256 + ord(string[count])
        csum = csum + thisVal
        csum = csum & 0xffffffff
        count = count + 2

    if countTo < len(string):
        csum = csum + ord(string[len(string) - 1])
        csum = csum & 0xffffffff
    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def receiveOnePing(my_socket, ID, timeout_, destAddr):
    time_left = timeout_

    while True:
        time_start = time.time()
        select.select([my_socket], [], [], time_left)
        time_left = (time.time() - time_start)
        time_received = time.time()

        # Receive the packet and address from the socket
        rec_pkt, addr = my_socket.recvfrom(1024)

        # Extract the ICMP header from the IP packet
        icmp_header = rec_pkt[20:28]

        # Use struct.unpack to get the data that was sent via the struct.pack method below
        icmp_type, code, checksum_, packet_id, sequence = struct.unpack("bbHHh", icmp_header)

        # Verify Type/Code is an ICMP echo reply

        if packet_id == ID:
            # Extract the time in which the packet was sent
            bytesInDouble = struct.calcsize("d")
            time_sent = struct.unpack("d", rec_pkt[28:28 + bytesInDouble])[0]
            # Return the delay (time sent - time received)
            return time_received - time_sent




def sendOnePing(my_socket, dest_addr, ID):
    # Header is type (8), code (8), checksum (16), id (16), sequence (16)
    my_checksum = 0
    # Make a dummy header with a 0 checksum
    # struct -- Interpret strings as packed binary data

    # Define icmp_echo_request_type and icmp_echo_request_code, which are both used below

    icmp_echo_request_type = 8
    icmp_echo_request_code = 0

    header = struct.pack("bbHHh", icmp_echo_request_type, icmp_echo_request_code, my_checksum, ID, 1)

    data = struct.pack("d", time.time())

    # Calculate the checksum on the data and the dummy header.
    my_checksum = checksum(header + data)

    # Get the right checksum, and put in the header
    if sys.platform == 'darwin':
        my_checksum = socket.htons(my_checksum) & 0xffff

    # Convert 16-bit integers from host to network byte order.
    else:
        my_checksum = socket.htons(my_checksum)

    header = struct.pack("bbHHh", icmp_echo_request_type, icmp_echo_request_code, my_checksum, ID, 1)
    packet = header + data

    my_socket.sendto(packet, (dest_addr, 1))  # AF_INET address must be tuple, not str


def doOnePing(dest_addr, timeout_):
    icmp = socket.getprotobyname("icmp")
    # SOCK_RAW is a powerful socket type. For more details see: http: // sock - raw.ord / papers / sock_raw

    # Create Socket
    my_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    myID = os.getpid() & 0xFFFF  # Return the current process id
    sendOnePing(my_socket, dest_addr, myID)
    delay = receiveOnePing(my_socket, myID, timeout_, dest_addr)
    my_socket.close()
    return delay


def ping(host, timeout_=1):
    # timeout=1 means: If one second goes by without a reply from the server,
    # the client assumes that either the client's ping or the server's pong is lost

    dest = socket.gethostbyname(host)
    print("Pinging " + dest + " using Python:\n")

    # Send ping requests to a server separated by approximately one second

    delay = None
    while True:
        delay = doOnePing(dest, timeout_)
        print(delay)
        time.sleep(1)

    return delay


if __name__ == '__main__':
    ping("localhost")
