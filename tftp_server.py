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
        self.fname = "a.txt"
        pass

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

        if opcode == 1 or opcode == 2:
            first_zero_idx = bytesarray.index(0,1)   # do not search from the first index to avoid the "0" in the "opcode" field
            filename_len = first_zero_idx - 2   # 2 is the length of the opcode
            format_string += str(filename_len) + "sc"
            sec_zero_idx = bytesarray.index(0,first_zero_idx + 1)    # find the index of the second zero which terminates the "mode" field
            mode_len = sec_zero_idx - first_zero_idx - 1
            format_string += str(mode_len) + "sc"
        elif opcode == 3:
            format_string += "h"
            format_string += str(len(bytesarray) - 4) + "s"
        elif opcode == 4:
            format_string += "h"
        elif opcode == 5:
            format_string += "h"
            format_string += str(len(bytesarray) - 5) + "sc"

        print("opcode: " , opcode)
        print("format string: ", format_string)
        print("packet list: ",struct.unpack(format_string, packet_bytes))
        return struct.unpack(format_string, packet_bytes)

    def _get_bytes_from_file(self, filename):  
        return open(filename, "rb").read()

    def _do_some_logic(self, input_packet):
        """
        Example of a private function that does some logic.
        """
        format_string = "!h"
        packed_data = ""

        if input_packet[0] == 1:
            filename = input_packet[1].decode("ascii")
            print(filename)
            bytesarray = self._get_bytes_from_file(filename)
            print(bytesarray) 
            top512 = bytesarray[:512] 
            print(top512)
    
            format_string += "h" + str(len(top512)) + "s"
            packed_data = struct.pack(format_string, 3, 1, top512)

            print(list(packed_data))
        
        elif input_packet[0] == 2:
            format_string += "h"
            packed_data = struct.pack(format_string, 4, 0)
        elif input_packet[0] == 3:
            format_string += "h"
            block_number = input_packet[1]
            packed_data = struct.pack(format_string, 4, block_number)
            newfile = open(self.fname, "ab")
            newfile.write(input_packet[2])


        return packed_data

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

    recv_send_packets(sock)

def recv_send_packets(sock):
    while(1):
        rec_packet = sock.recvfrom(4096)
        print("received packet: ", rec_packet)
        tftp = do_socket_logic(rec_packet)
        if tftp.has_pending_packets_to_be_sent():
            print("packets available")
            packet = tftp.get_next_output_packet()
            print(packet)
            sock.sendto(packet, rec_packet[1])

def do_socket_logic(udp_packet):
    """
    Example function for some helper logic, in case you
    want to be tidy and avoid stuffing the main function.
    Feel free to delete this function.
    """
    tftpproc = TftpProcessor()
    tftpproc.process_udp_packet(udp_packet[0], udp_packet[1])

    return tftpproc

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