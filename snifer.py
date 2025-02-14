import time
import sys
from scapy.all import sniff
from colorama import Fore, Style, init
from prettytable import PrettyTable


# Function to pause and exit
def pause_and_exit(sleep_time):
    # Pause the program for the specified time
    time.sleep(sleep_time)
    print(f"Paused for {sleep_time} seconds.")
    print("Time is up! Stopping the sniffing process...")

# Callback function to process packets and print them in table format
def packet_callback(packet, table):
    if packet.haslayer("IP"):
        src_ip = packet["IP"].src
        dst_ip = packet["IP"].dst
        protocol = packet["IP"].proto  # Protocol (6=TCP, 17=UDP, 1=ICMP)
        
        # Check if it has a transport layer (TCP or UDP)
        src_port = packet["TCP"].sport if packet.haslayer("TCP") else (packet["UDP"].sport if packet.haslayer("UDP") else "N/A")
        dst_port = packet["TCP"].dport if packet.haslayer("TCP") else (packet["UDP"].dport if packet.haslayer("UDP") else "N/A")

        # Add packet details to the table
        table.add_row([src_ip, f"{src_port}", dst_ip, f"{dst_port}", protocol])

        # Append packet details to packet_data list for saving to file
        packet_data.append(f"{src_ip} -> {dst_ip} | {src_port}:{dst_port} | Protocol: {protocol}")

# Function to initialize and print the table header
def print_table():
    # Initialize a PrettyTable object
    table = PrettyTable()

    # Define column names (headers)
    table.field_names = ["Source", "Source Port", "Destination", "Destination Port", "Protocol"]

    return table

def save_to_file():
    # Ask the user if they want to save the results to a text file
    save = input("Do you want to save the captured packets to a text file? (yes/no): ").lower()
    if save == 'yes':
        with open("captured_packets.txt", "w") as f:
            for data in packet_data:
                f.write(data + "\n")
        print("Captured packets have been saved to 'captured_packets.txt'.")
    else:
        print("Captured packets not saved.")


# Main function to run the sniffing process
def main():
    print(Fore.GREEN + """
▄▄▄█████▓ ██▀███   ▄▄▄        █████▒ █████▒██▓ ▄████▄       ██████  ███▄    █  ██▓  █████▒ █████▒▓█████  ██▀███  
▓  ██▒ ▓▒▓██ ▒ ██▒▒████▄    ▓██   ▒▓██   ▒▓██▒▒██▀ ▀█     ▒██    ▒  ██ ▀█   █ ▓██▒▓██   ▒▓██   ▒ ▓█   ▀ ▓██ ▒ ██▒
▒ ▓██░ ▒░▓██ ░▄█ ▒▒██  ▀█▄  ▒████ ░▒████ ░▒██▒▒▓█    ▄    ░ ▓██▄   ▓██  ▀█ ██▒▒██▒▒████ ░▒████ ░ ▒███   ▓██ ░▄█ ▒
░ ▓██▓ ░ ▒██▀▀█▄  ░██▄▄▄▄██ ░▓█▒  ░░▓█▒  ░░██░▒▓▓▄ ▄██▒     ▒   ██▒▓██▒  ▐▌██▒░██░░▓█▒  ░░▓█▒  ░ ▒▓█  ▄ ▒██▀▀█▄  
  ▒██▒ ░ ░██▓ ▒██▒ ▓█   ▓██▒░▒█░   ░▒█░   ░██░▒ ▓███▀ ░   ▒██████▒▒▒██░   ▓██░░██░░▒█░   ░▒█░    ░▒████▒░██▓ ▒██▒
  ▒ ░░   ░ ░▓ ░▒▓░ ▒▒   ▓▒█░ ▒ ░    ▒ ░   ░▓  ░ ░▒ ▒  ░   ▒ ▒▓▒ ▒ ░░ ░░   ░ ▒ ░▓   ▒ ░    ▒ ░    ░░ ▒░ ░░ ▒▓ ░▒▓░
    ░      ░▒ ░ ▒░  ▒   ▒▒ ░ ░      ░      ▒ ░  ░  ▒      ░ ░▒  ░ ░░ ░░   ░ ▒░ ▒ ░ ░      ░       ░ ░  ░  ░▒ ░ ▒░
  ░        ░░   ░   ░   ▒    ░ ░    ░ ░    ▒ ░░           ░  ░  ░     ░   ░ ░  ▒ ░ ░ ░    ░ ░       ░     ░░   ░ 
            ░           ░  ░               ░  ░ ░               ░           ░  ░                    ░  ░   ░ BY UKI     
                                              ░                                                                  
                                                                                                              \n  """)

    # Ask the user to input the time in seconds
    sleep_time = input("Enter the time (in seconds) to sniff traffic: ")

    try:
        # Convert the input to an integer
        sleep_time = int(sleep_time)

        # Initialize the table
        table = print_table()

        # Print message before starting sniffing
        print(f"Sniffing network traffic for {sleep_time} seconds...")
        global packet_data
        packet_data = []


        # Start sniffing with a timeout to automatically stop after sleep_time seconds
        sniff(prn=lambda packet: packet_callback(packet, table), store=False, timeout=sleep_time)

        # Print the table after sniffing ends
        print(table)

        # After sniffing ends, call the pause_and_exit function
        pause_and_exit(sleep_time)
        save_to_file()

    except ValueError:
        print("Invalid input! Please enter a valid number.")

# Run the main function
main()
