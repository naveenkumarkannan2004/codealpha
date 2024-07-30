import scapy.all as scapy
def sniffer(interface):
    scapy.sniff(iface=interface, store=False ,prn=process_packet)
def process_packet(packet):
    print(packet.summary())
interface = "Wi-Fi"  

if __name__ == "__main__":
    try:
        sniffer(interface)
    except PermissionError:
        print("Permission denied. Please run as root or administrator.")
    except Exception as e:
        print(f"An error occurred: {e}")
