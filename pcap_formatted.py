"""
This script generates explanations for the outputs of a network intrusion detection system (NIDS).
It uses the Gemini API to generate explanations for the outputs.
It then extracts relevant information from the Gemini response and formats it as a detailed report.
Created by Andres Haro, 2023. 
"""
from dotenv import load_dotenv
from scapy.all import rdpcap
import google.generativeai as genai
import os
import time

load_dotenv()

# Set your Gemini API key
genai.configure(api_key=os.getenv("GEMINI_API_KEY"))
# Pring the API key to verify it is being read
# print(os.getenv("GEMINI_API_KEY"))

# Initialize the Gemini model
model = genai.GenerativeModel("gemini-pro")

# Function to generate explanation for a given packet summary
def generate_explanation(packet_summary):
    prompt = f"Explain the following network packet:\n{packet_summary}"
    try:
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"Error generating explanation: {e}")
        return "Error generating explanation."

# Function to extract relevant packet details
def extract_packet_details(packet):
    details = {
        "Source IP": packet[0][1].src if packet.haslayer('IP') else "N/A",
        "Destination IP": packet[0][1].dst if packet.haslayer('IP') else "N/A",
        "Protocol": packet[0][1].proto if packet.haslayer('IP') else "N/A",
        "Payload Size": len(packet.payload),
        "Summary": packet.summary(),
    }
    return details

# Function to dynamically generate solutions based on the explanation
def generate_solutions(explanation):
    solutions = []

    # Use Gemini to analyze the explanation and generate tailored solutions
    prompt = f"Identify potential security vulnerabilities and suggest solutions based on the following explanation: {explanation}"

    try:
        response = model.generate_content(prompt)
        gemini_solutions = response.text.strip().split('\n')
        solutions.extend(gemini_solutions)
    except Exception as e:
        print(f"Error generating solutions: {e}")
        solutions.append("Error generating solutions.")

    return solutions



# Function to format the packet information and explanation as a detailed report
def format_report(packet_details, explanation):
    report = f"Packet Analysis Report:\n\n"
    report += f"Source IP: {packet_details['Source IP']}\n"
    report += f"Destination IP: {packet_details['Destination IP']}\n"
    report += f"Protocol: {packet_details['Protocol']}\n"
    report += f"Payload Size: {packet_details['Payload Size']} bytes\n"
    report += f"Summary: {packet_details['Summary']}\n\n"
    report += f"Explanation:\n{explanation}\n\n"
    report += "Possible Solutions:\n"
    solutions = generate_solutions(explanation)
    for solution in solutions:
        report += f"- {solution}\n"
    return report

# Function to process all .pcap files in a folder
def process_folder(input_folder, output_folder):
    # List all .pcap files in the input folder
    input_files = [f for f in os.listdir(input_folder) if f.endswith('.pcap')]

    for input_file in input_files:
        input_file_path = os.path.join(input_folder, input_file)
        output_file_name = os.path.splitext(input_file)[0] + ".txt"
        output_file_path = os.path.join(output_folder, output_file_name)

        try:
            start_time = time.time()
            # Read packets from the pcap file
            packets = rdpcap(input_file_path)

            full_report = ""

            for idx, packet in enumerate(packets[:20]):
                packet_details = extract_packet_details(packet)
                start_time = time.time()
                print(f"Time to generate explanation for packet {idx + 1}: {time.time() - start_time} seconds")
                explanation = generate_explanation(packet_details['Summary'])
                report = format_report(packet_details, explanation)
                full_report += f"Packet {idx + 1}:\n{report}\n{'-' * 80}\n"

            # Save the full report to the output file
            start_time = time.time()
            with open(output_file_path, 'w') as file:
                file.write(full_report)

            print(f"Report generated and saved: {output_file_path}")
            print(f"Time to save report: {time.time() - start_time} seconds")

        except Exception as e:
            print(f"Error processing file {input_file}: {e}")

# Input and output folder paths
input_folder_path = "/Users/alanharo/Documents/GitHub/PcapAnalyzer/pcap_file"
output_folder_path = "/Users/alanharo/Documents/GitHub/PcapAnalyzer/Better_Outputs"

# Create the output folder if it doesn't exist
os.makedirs(output_folder_path, exist_ok=True)

# Process the folder and generate explanations
process_folder(input_folder_path, output_folder_path)

print("Reports generated and saved to the output folder.")
