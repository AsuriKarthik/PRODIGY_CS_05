import tkinter as tk
from tkinter import messagebox
from scapy.all import sniff

# Function to start sniffing packets
def start_sniffing():
    # Start sniffing packets in a separate thread
    sniff(prn=process_packet, count=10)  # Adjust count as needed

# Function to process each packet
def process_packet(packet):
    # Extract relevant information from the packet
    try:
        src_ip = packet[1].src  # Assuming IP layer is at index 1
        dst_ip = packet[1].dst
        protocol = packet[1].proto  # Protocol number
        payload = packet.summary()  # Get a summary of the packet

        # Format the output
        output = f"Source IP: {src_ip}\n"
        output += f"Destination IP: {dst_ip}\n"
        output += f"Protocol: {protocol}\n"
        output += f"Payload: {payload}\n"
        output += "-" * 50 + "\n"

        # Insert the formatted output into the Text widget
        packet_text.insert(tk.END, output)
        packet_text.see(tk.END)  # Scroll to the end
    except Exception as e:
        print(f"Error processing packet: {e}")

# Function to show Wireshark suggestion
def show_wireshark_suggestion():
    messagebox.showinfo("Wireshark Suggestion", 
                        "For a more detailed analysis of packets, consider using Wireshark. "
                        "It provides a comprehensive interface for capturing and analyzing network traffic.")

# Create the main window
root = tk.Tk()
root.title("Packet Sniffer")

# Create a button to start sniffing
start_button = tk.Button(root, text="Start Sniffing", command=start_sniffing)
start_button.pack(pady=10)

# Create a button to show Wireshark suggestion
wireshark_button = tk.Button(root, text="Wireshark Suggestion", command=show_wireshark_suggestion)
wireshark_button.pack(pady=10)

# Create a Text widget to display captured packets
packet_text = tk.Text(root, width=70, height=20)
packet_text.pack(pady=10)

# Start the GUI event loop
root.mainloop()