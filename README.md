# Reputation_IP_VT
**Explanation:**

This Python script utilizes the VirusTotal API to perform a reputation check of IP addresses. It retrieves information such as the malicious count, Autonomous System Number (ASN) owner, and country associated with each IP address.

**Input:**

The script reads input from an Excel file (input.xlsx) containing a list of IP addresses. The first row is ignored, assuming it contains column headers.

**Output:**

The output is saved in an Excel file named output_date_time.xlsx in the "Result" folder. The columns include the IP address, VirusTotal malicious count, ASN owner, and country information.

**Dependencies:**

pandas: For handling Excel data.
requests: For making HTTP requests to the VirusTotal API.
colorama: For colored console output.
Usage:

Replace 'YOUR_VT_API_KEY' with your actual VirusTotal API key.
Provide the input Excel file (input.xlsx).
Run the script.
The results will be saved in the "Result" folder with a timestamped output file.
