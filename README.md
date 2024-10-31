## SubHasPwned
SubHasPwn is a Python-based tool designed to identify potential subdomain takeover vulnerabilities by analyzing CNAME records of specified subdomains.
The tool uses DNS resolution and HTTP requests to assess if a subdomain is vulnerable to takeover by matching CNAME records against known vulnerable services.

## Key Features

1. **CNAME Resolution**:
   - Resolves CNAME records for given subdomains to identify associated domains.
   - Checks if the resolved CNAME points to any known vulnerable services.

2. **Vulnerability Checking**:
   - Compares the resolved CNAME records against patterns of known vulnerable services.
   - Sends HTTP requests to determine if the service is active and potentially vulnerable.

3. **Multithreading Support**:
   - Supports concurrent processing of multiple subdomains using threads for efficient execution.
   - Allows the user to specify the number of threads to optimize performance.
  
## Usage

To use the Subdomain Takeover Checker, follow these steps:

1. **Install Required Libraries**:
   - Ensure you have the required libraries installed. You can install them using pip:
     ```bash
     pip install dnspython requests beautifulsoup4 coloredlogs pyyaml
     ```

2. **Prepare the Input File**:
   - Create a text file containing the list of subdomains you wish to check, with one subdomain per line.

3. **Create a Configuration File**:
   - Create a `vulnerable.yaml` file that contains patterns and response messages for known vulnerable services. This file is used to identify potential takeovers.

4. **Run the Tool**:
   - Execute the script from the command line, providing the path to the subdomain file and optionally specifying the number of threads. For example:
     ```bash
     python main.py -f subdomains.txt -t 10
     ```

5. **Review the Results**:
   - After execution, check the output file (default: `takeover.txt`) for a list of vulnerable subdomains and their associated details.
