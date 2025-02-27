import sys
import os
import enum
import socket
import struct 


class TftpProcessor(object):
    """
    Implements logic for a TFTP server.
    The input to this object is a received UDP packet,
    the output is the packets to be written to the socket.
    This class MUST NOT know anything about the existing sockets
    its input and outputs are byte arrays ONLY.
    Store the output packets in a buffer (some list) in this class
    the function get_next_output_packet returns the first item in
    the packets to be sent.
    This class is also responsible for reading/writing files to the
    hard disk.
    Failing to comply with those requirements will invalidate
    your submission.
    Feel free to add more functions to this class as long as
    those functions don't interact with sockets nor inputs from
    user/sockets. For example, you can add functions that you
    think they are "private" only. Private functions in Python
    start with an "_", check the example below
    """

    class TftpPacketType(enum.Enum):
        """
        Represents a TFTP packet type add the missing types here and
        modify the existing values as necessary.
        """
        RRQ = 1
        WRQ = 2
        DATA = 3
        ACK = 4
        ERROR = 5

    def __init__(self):
        """
        Add and initialize the *internal* fields you need.
        Do NOT change the arguments passed to this function.
        Here's an example of what you can do inside this function.
        """
        self.packet_buffer = []
        self.output_fname = ""
        self.input_bytesarr = []

        self.errors = {0: "Not defined, see error message (if any).", 
                       1: "File not found.",
                       4: "Illegal TFTP operation.",
                       6: "File already exists."}

        self.caddress = None
        self.last_block_num = -1
        self.termination_flag = 0

    def reset(self):
        self.termination_flag = 0
        self.packet_buffer = []
        self.output_fname = ""
        self.input_bytesarr = []
        self.caddress = None
        self.last_block_num = -1

    def process_udp_packet(self, packet_data, packet_source):
        """
        Parse the input packet, execute your logic according to that packet.
        packet data is a bytearray, packet source contains the address
        information of the sender.
        """
        # Add your logic here, after your logic is done,
        # add the packet to be sent to self.packet_buffer
        # feel free to remove this line
        print(f"Received a packet from {packet_source}")
        in_packet = self._parse_udp_packet(packet_data)
        out_packet = self._do_some_logic(in_packet)

        # This shouldn't change.
        self.packet_buffer.append(out_packet)

    def _parse_udp_packet(self, packet_bytes):
        """
        You'll use the struct module here to determine
        the type of the packet and extract other available
        information.
        """

        bytesarray = list(packet_bytes)
        opcode = bytesarray[1]
        format_string = "!h"

        if opcode == TftpProcessor.TftpPacketType.RRQ.value or opcode == TftpProcessor.TftpPacketType.WRQ.value:
            first_zero_idx = bytesarray.index(0,1)   # do not search from the first index to avoid the "0" in the "opcode" field
            filename_len = first_zero_idx - 2   # 2 is the length of the opcode
            format_string += str(filename_len) + "sc"
            sec_zero_idx = bytesarray.index(0,first_zero_idx + 1)    # find the index of the second zero which terminates the "mode" field
            mode_len = sec_zero_idx - first_zero_idx - 1
            format_string += str(mode_len) + "sc"
            
            del( bytesarray[sec_zero_idx+1:] )
            packet_bytes = packet_bytes[:sec_zero_idx+1]


        elif opcode == TftpProcessor.TftpPacketType.DATA.value:
            format_string += "h" + str(len(bytesarray) - 4) + "s"
            
            if len(bytesarray) - 4 < 512:
                self.termination_flag = 2

        elif opcode == TftpProcessor.TftpPacketType.ACK.value:
            format_string += "h"

            if self.termination_flag == 1:
                self.termination_flag = 3

            packet_bytes = packet_bytes[:4]
            print("printing now")
            print(packet_bytes)

        elif opcode == TftpProcessor.TftpPacketType.ERROR.value:
            zero_idx = bytesarray.index(0, 4)
            format_string += "h" + str(zero_idx-4) + "sc"
            
            packet_bytes = packet_bytes[:zero_idx+1]
            print("printing now in ERROR elif")
            print(packet_bytes)
        else:
            err = bytearray([0,6])
            return list(struct.unpack("!h", err))

        print("opcode: " , opcode)
        print("format string: ", format_string)
        print("packet list: ",struct.unpack(format_string, packet_bytes))
        return list(struct.unpack(format_string, packet_bytes))

    def _get_bytes_from_file(self, filename): 
        try:
            return open(filename, "rb").read()
        except FileNotFoundError:
            return None

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        format_string = "!h"
        packed_data = ""

        if input_packet[0] == TftpProcessor.TftpPacketType.RRQ.value:
            filename = input_packet[1].decode("ascii")
            print(filename)
            self.input_bytesarr = self._get_bytes_from_file(filename)
            if self.input_bytesarr != None:
                print("file: ",self.input_bytesarr) 
                top512 = self.input_bytesarr[:512] 
                print(top512)

                if (len(top512) < 512):
                    self.termination_flag = 1

                format_string += "h" + str(len(top512)) + "s"
                packed_data = struct.pack(format_string, 3, 1, top512)

                print(list(packed_data))
            else:
                self.termination_flag = 2
                format_string += "h" + str(len(self.errors[1])) + "sB"
                packed_data = struct.pack(format_string, 5, 1, self.errors[1].encode("ascii"), 0)

            
        elif input_packet[0] == TftpProcessor.TftpPacketType.WRQ.value:
            format_string += "h"
            packed_data = struct.pack(format_string, 4, 0)

            self.output_fname = input_packet[1].decode("ascii")

        elif input_packet[0] == TftpProcessor.TftpPacketType.DATA.value:
            block_number = input_packet[1]

            #if self.check_and_set_blknum(block_number) == -1:
             #   return None

            format_string += "h"
            if block_number == 1:
                newfile = open(self.output_fname, "wb")
            else:
                newfile = open(self.output_fname, "ab")
            newfile.write(input_packet[2])
            
            packed_data = struct.pack(format_string, 4, block_number)

        elif input_packet[0] == TftpProcessor.TftpPacketType.ACK.value:

            #if self.check_and_set_blknum(input_packet[1]) == -1:
             #   return None

            block_number = input_packet[1]+1
            subseq512 = self.input_bytesarr[512 * (block_number - 1): block_number*512: 1]
            print("subseq: ", subseq512)

            if len(subseq512) < 512 and self.termination_flag != 3:
                self.termination_flag = 1

            format_string += "h" + str(len(subseq512)) + "s"
            packed_data = struct.pack(format_string, 3, block_number, subseq512)
        else:
            self.termination_flag = 2
            format_string += "h" + str(len(self.errors[4])) + "sB"
            packed_data = struct.pack(format_string, 5, 4, self.errors[4].encode("ascii"), 0)


        return packed_data

    def check_and_set_blknum(self, blknum):
        if self.last_block_num == -1 or self.last_block_num < blknum:
            self.last_block_num = blknum
            return 1
        else:
            return -1 

    def get_next_output_packet(self):
        """
        Returns the next packet that needs to be sent.
        This function returns a byetarray representing
        the next packet to be sent.
        For example;
        s_socket.send(tftp_processor.get_next_output_packet())
        Leave this function as is.
        """
        return self.packet_buffer.pop(0)

    def has_pending_packets_to_be_sent(self):
        """
        Returns if any packets to be sent are available.
        Leave this function as is.
        """
        return len(self.packet_buffer) != 0


def check_file_name():
    script_name = os.path.basename(__file__)
    import re
    matches = re.findall(r"(\d{4}_)+lab1\.(py|rar|zip)", script_name)
    if not matches:
        print(f"[WARN] File name is invalid [{script_name}]")
    pass


def setup_sockets(address):
    """
    Socket logic MUST NOT be written in the TftpProcessor
    class. It knows nothing about the sockets.
    Feel free to delete this function.
    """
    # don't forget, the server's port is 69 (might require using sudo on Linux)
    print(f"TFTP server started on on [{address}]...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    serv_address = (address, 69)
    sock.bind(serv_address)
    sock.settimeout(500)
    recv_send_packets(sock)

def recv_send_packets(sock):

    tftpproc = TftpProcessor()

    while(1):
        rec_packet = sock.recvfrom(4096)
        if tftpproc.caddress == None:
            tftpproc.caddress = rec_packet[1]
        elif rec_packet[1][0] != tftpproc.caddress[0]:
            continue
        print("received packet: ", rec_packet)
        tftpproc.process_udp_packet(rec_packet[0], rec_packet[1])
        if tftpproc.has_pending_packets_to_be_sent():
            print("packets available")
            packet = tftpproc.get_next_output_packet()
            print(packet)
            if tftpproc.termination_flag == 3:
                tftpproc.reset()
                continue
            sock.sendto(packet, rec_packet[1])
            if tftpproc.termination_flag == 2:
                tftpproc.reset()

def get_arg(param_index, default=None):
    """
        Gets a command line argument by index (note: index starts from 1)
        If the argument is not supplies, it tries to use a default value.
        If a default value isn't supplied, an error message is printed
        and terminates the program.
    """
    try:
        return sys.argv[param_index]
    except IndexError as e:
        if default:
            return default
        else:
            print(e)
            print(
                f"[FATAL] The comamnd-line argument #[{param_index}] is missing")
            exit(-1)    # Program execution failed.


def main():
    """
     Write your code above this function.
    if you need the command line arguments
    """
    print("*" * 50)
    print("[LOG] Printing command line arguments\n", ",".join(sys.argv))
    check_file_name()
    print("*" * 50)

    # This argument is required.
    # For a server, this means the IP that the server socket
    # will use.
    # The IP of the server.
    ip_address = get_arg(1, "127.0.0.1")
    setup_sockets(ip_address)


if __name__ == "__main__":
    main()