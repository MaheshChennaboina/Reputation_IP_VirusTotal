"""
Explaination: Reputation check of IP using VirusTotal API
Input:
The script reads input from an Excel file (input.xlsx) containing a list of IP addresses.
The first row is ignored, assuming it contains column headers.
Output:
The output is saved in an Excel file named output_date_time.xlsx in the "Result" folder.
The columns include the IP address, VirusTotal malicious count, ASN owner, and country information.
"""
import os
import requests
import pandas as pd
from datetime import datetime
from colorama import Fore, Style, init

# Initialize Colorama
init(autoreset=True)

def get_virustotal_info(api_key, ip_address):
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': api_key}

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        malicious_count = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        
        # Modify this line based on the actual structure of the response
        asn_owner = data.get('data', {}).get('attributes', {}).get('as_owner', '')
        
        # Include the country information
        country = data.get('data', {}).get('attributes', {}).get('country', {})
   

        return malicious_count, asn_owner, country
    elif response.status_code == 404:
        print(f'{Fore.RED}IP address {ip_address} not found on VirusTotal.{Style.RESET_ALL}')
    else:
        print(f'{Fore.RED}Error: {response.status_code}{Style.RESET_ALL}')

    return 0, '', ''

def process_excel(input_file, output_file, vt_api_key):
    df = pd.read_excel(input_file, header=None, names=['IP'], skiprows=1)

    results = []

    for index, row in df.iterrows():
        ip_address = row['IP']
        
        # Display processing message with colored output
        print(f'{Fore.GREEN}Processing IP: {ip_address}...', end=' ')
        
        vt_malicious_count, vt_asn_owner, vt_country = get_virustotal_info(vt_api_key, ip_address)
        
        # Display the number of malicious count
        print(f'Malicious Count: {vt_malicious_count}{Style.RESET_ALL}')

        results.append({
            'IP': ip_address,
            'VT_Malicious_Count': vt_malicious_count,
            'VT_ASN_Owner': vt_asn_owner,
            'VT_Country': vt_country,
        })

    output_df = pd.DataFrame(results)

    # Check if the "Result" folder exists, if not, create it
    result_folder = 'Result'
    if not os.path.exists(result_folder):
        os.makedirs(result_folder)

    output_path = os.path.join(result_folder, output_file)
    output_df.to_excel(output_path, index=False)

if __name__ == "__main__":
    # Replace 'YOUR_VT_API_KEY' with your actual VirusTotal API key
    vt_api_key = '029455493eb333bf6e839263f7375ceb5a97db5845de1b3646775188a7879269'

    # Replace 'input.xlsx' and 'output_' with your actual input file and desired output file prefix
    input_file = 'input.xlsx'
    output_file = f'output_{datetime.now().strftime("%Y%m%d_%H%M%S")}.xlsx'

    process_excel(input_file, output_file, vt_api_key)

    print(f'{Fore.YELLOW}Results saved to the "Result" folder in {output_file}{Style.RESET_ALL}')
