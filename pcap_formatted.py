import openai
from dotenv import load_dotenv
import os
import re

# Load environment variables from .env
load_dotenv()

# API Key check with more informative error message
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY environment variable not set.  Please create a .env file and add it.")

client = openai.OpenAI(api_key=api_key)

def generate_explanation(output_text):
    prompt = f"Explain the following network security log:\n{output_text}"
    try:
        response = client.chat.completions.create(
            model="gpt-4",  # Use "gpt-3.5-turbo" if GPT-4 is unavailable
            messages=[
                {"role": "system", "content": "You are an AI that explains cybersecurity logs.  Be concise and focus on key details."},
                {"role": "user", "content": prompt}
            ],
            max_tokens=800,
            temperature=0.2 # Lower temperature for more deterministic and factual responses
        )
        return response.choices[0].message.content.strip()
    except Exception as e:  # Catch any exception
        print(f"Error communicating with OpenAI API: {e}")  # Print the error for debugging
        return None

def extract_information(gpt_response):
    if not gpt_response:  # Handle cases where GPT API call failed
        return {}

    information = {}

    # Use regular expressions for more robust extraction (examples)
    match = re.search(r"Source IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", gpt_response)
    if match:
        information["Source IP"] = match.group(1)

    match = re.search(r"Destination IP:\s*(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", gpt_response)
    if match:
        information["Destination IP"] = match.group(1)

    match = re.search(r"Host:\s*([\w.-]+)", gpt_response)
    if match:
        information["Host"] = match.group(1)

    match = re.search(r"Vulnerability Type:\s*(.+)", gpt_response, re.IGNORECASE) # Case insensitive
    if match:
        information["Type of vulnerability"] = match.group(1).strip()

    match = re.search(r"User-Agent:\s*(.+)", gpt_response)
    if match:
        information["User-Agent"] = match.group(1).strip()

    match = re.search(r"Request Type:\s*(.+)", gpt_response)
    if match:
        information["Request Type"] = match.group(1).strip()

    match = re.search(r"Status Code:\s*(\d{3})", gpt_response)
    if match:
        information["Status Code"] = match.group(1).strip()

    # ... (Add more regex extractions for other fields)

    # Default values if not found
    information.setdefault("Source IP", "N/A")
    information.setdefault("Destination IP", "N/A")
    information.setdefault("Host", "N/A")
    information.setdefault("Type of vulnerability", "N/A")
    information.setdefault("User-Agent", "N/A")
    information.setdefault("Request Type", "N/A")
    information.setdefault("Status Code", "N/A")
    # ... set defaults for other fields

    return information


def generate_solutions(vulnerability_type):
    solutions_dict = {  # More comprehensive solutions
        "SQL Injection": [
            "Use parameterized queries or prepared statements.",
            "Implement input validation and sanitization.",
            "Apply least privilege principles to database accounts.",
            "Use a Web Application Firewall (WAF)."
        ],
        "Cross-Site Scripting (XSS)": [ # Corrected name
            "Encode output using context-appropriate escaping functions (e.g., HTML escaping).",
            "Implement Content Security Policy (CSP).",
            "Use HTTP-only cookies to mitigate XSS-based cookie theft.",
            "Sanitize user input by removing or escaping potentially dangerous characters."
        ],
        "Default": ["Implement secure coding practices.", "Regularly patch and update systems.", "Conduct security audits and penetration testing."]
    }
    # Handle variations in vulnerability type casing
    vulnerability_type = vulnerability_type.lower()
    for key in solutions_dict:
        if key.lower() == vulnerability_type:
            return solutions_dict[key]
    return solutions_dict["Default"]


def format_report(information):
    report = "Report:\n\n"
    for key, value in information.items():  # Dynamic report generation
        report += f"{key}: {value}\n"

    report += "\nPossible Solutions:\n"
    solutions = generate_solutions(information.get("Type of vulnerability", "Default")) # Handle missing type
    for solution in solutions:
        report += f"- {solution}\n"

    return report


def process_folder(input_folder, output_folder):
    for input_file in os.listdir(input_folder):
        input_file_path = os.path.join(input_folder, input_file)
        output_file_path = os.path.join(output_folder, input_file + ".txt") # Add .txt extension

        try:
            with open(input_file_path, 'r', encoding="utf-8", errors="ignore") as file:
                input_text = file.read()

            explanation = generate_explanation(input_text)

            if explanation is None:  # Handle OpenAI API errors gracefully
                print(f"Failed to generate explanation for {input_file}. Skipping.")
                continue

            information = extract_information(explanation)
            report = format_report(information)

            with open(output_file_path, 'w', encoding="utf-8") as file:
                file.write(report)

        except Exception as e:  # Catch and report file processing errors
            print(f"Error processing file {input_file}: {e}")


# Input and output folder paths
input_folder_path = "./pcap_file"  # Or wherever your pcap files are
output_folder_path = "/Users/alanharo/Documents/GitHub/PcapAnalyzer/Better_Outputs" # Your output path

# Ensure output folder exists
os.makedirs(output_folder_path, exist_ok=True)

# Process the folder and generate explanations
process_folder(input_folder_path, output_folder_path)

print("Reports generated and saved to Better_Outputs folder.")