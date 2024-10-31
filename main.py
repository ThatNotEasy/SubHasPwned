import os
import logging
import coloredlogs
import dns.resolver
import requests, random
import yaml, argparse
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from colorama import Fore, Style

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
coloredlogs.install(level='INFO', logger=logger)

def clear_terminal():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_colored_banner(banner):
    for line in banner.strip().split('\n'):
        color = random.choice([Fore.RED, Fore.GREEN, Fore.YELLOW, Fore.BLUE, Fore.MAGENTA, Fore.CYAN, Fore.WHITE])
        print(color + line + Style.RESET_ALL)

def get_page_title(content):
    try:
        soup = BeautifulSoup(content, 'html.parser')
        title = soup.title.string if soup.title else None
        if not title and '<?xml' in content.decode('utf-8', 'ignore'):
            soup = BeautifulSoup(content, 'lxml-xml')
            title = soup.find('title')
        return title.strip() if title else 'No title'
    except Exception as e:
        logger.error(f"Error fetching title: {e}")
        return 'Error fetching title'

def get_cname(subdomain):
    try:
        logger.info(f"{Fore.YELLOW}[SubHasPwned]: {Fore.WHITE}Resolving CNAME for: {Fore.GREEN}{subdomain}{Fore.RESET}")
        parsed_url = urlparse(subdomain)
        domain = parsed_url.netloc or parsed_url.path

        # Use dns.resolver.resolve() instead of dns.resolver.query()
        answers = dns.resolver.resolve(domain, 'CNAME')
        cname = [rdata.target.to_text().rstrip('.') for rdata in answers]

        logger.info(f"{Fore.YELLOW}[SubHasPwned]: {Fore.WHITE}Resolved CNAME for: {Fore.GREEN}{domain}: {Fore.WHITE}{cname}{Fore.RESET}")

        if cname:  # Check if CNAME is found before proceeding to A records
            try:
                ip_answers = dns.resolver.resolve(cname[0], 'A')
                ips = [ip.address for ip in ip_answers]
                logger.info(f"{Fore.YELLOW}[SubHasPwned]: {Fore.WHITE}CNAME {Fore.GREEN}{cname[0]} resolves to IP(s): {Fore.RED}{', '.join(ips)}{Fore.RESET}")
            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                logger.warning(f"{Fore.YELLOW}[SubHasPwned]: {Fore.WHITE}No A records found for CNAME: {Fore.RED}{cname[0]}{Fore.RESET}")
        return cname

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout) as e:
        logger.error(f"DNS resolution failed for {subdomain}: {e}")
        return []
    except Exception as e:
        logger.error(f"Unknown error while resolving CNAME for {subdomain}: {e}")
        return []

def check_subdomain_takeover(subdomain, output_file):
    cname_records = get_cname(subdomain)
    if cname_records:
        for cname in cname_records:
            is_potentially_vulnerable = False
            for service in vulnerable_services:
                for pattern in service["cname_patterns"]:
                    if pattern in cname:
                        is_potentially_vulnerable = True
                        result = f"[+] {subdomain} has CNAME {cname} matching {pattern}"
                        logger.info(result)
                        check_service_takeover(subdomain, cname, service, output_file)
                        break
                if is_potentially_vulnerable:
                    break
            if not is_potentially_vulnerable:
                result = f"[-] {subdomain} has CNAME {cname} but no matching vulnerable service"
                logger.warning(result)
    else:
        result = f"[-] {subdomain} has no CNAME record"
        logger.warning(result)

def check_service_takeover(subdomain, cname, service, output_file):
    try:
        for protocol in ['https://', 'http://']:
            url = f"{protocol}{subdomain}"
            logger.info(f"Trying {url}")
            response = requests.get(url, timeout=10, verify=False)
            status_code = response.status_code
            title = get_page_title(response.content)
            response_text = response.text
            for error_msg in service["response_messages"]:
                if error_msg.lower() in response_text.lower():
                    result = f"[+] {subdomain} [{status_code}] [{title}] [Vulnerable to {service['service']}]"
                    logger.success(result)
                    with open(output_file, 'a') as f:
                        f.write(f"{subdomain} [Vulnerable to {service['service']}]\n")
                    return
            logger.info(f"Checked {subdomain}: {status_code} - Not vulnerable")
        result = f"[-] {subdomain} [{status_code}] [{title}] [Not Vulnerable]"
        logger.warning(result)
    except requests.exceptions.SSLError:
        result = f"[-] {subdomain} [SSL Error]"
        logger.warning(result)
    except requests.exceptions.Timeout:
        result = f"[-] {subdomain} [Timeout] [No response within 10 seconds]"
        logger.warning(result)
    except requests.exceptions.RequestException as e:
        result = f"[-] {subdomain} [Error] [Could not connect: {e}]"
        logger.warning(result)

def process_subdomain(subdomain, output_file):
    check_subdomain_takeover(subdomain, output_file)

def main(file_path, output_file, threads):
    with open(output_file, 'w') as f:
        f.write("Vulnerable URLs:\n")

    try:
        with open(file_path, 'r') as file:
            domains = [line.strip() for line in file.readlines()]
    except FileNotFoundError:
        logger.error(f"Error: File {file_path} not found.")
        return
    
    if domains:
        logger.info(f"Found {len(domains)} subdomains to check.")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = [executor.submit(process_subdomain, subdomain, output_file) for subdomain in domains]
            for future in as_completed(futures):
                future.result() 
    else:
        logger.warning("No domains found in the file.")

if __name__ == "__main__":
    clear_terminal()
    banner = """
███████╗██╗   ██╗██████╗ ██╗  ██╗ █████╗ ███████╗██████╗ ██╗    ██╗███╗   ██╗███████╗██████╗     
██╔════╝██║   ██║██╔══██╗██║  ██║██╔══██╗██╔════╝██╔══██╗██║    ██║████╗  ██║██╔════╝██╔══██╗    
███████╗██║   ██║██████╔╝███████║███████║███████╗██████╔╝██║ █╗ ██║██╔██╗ ██║█████╗  ██║  ██║    
╚════██║██║   ██║██╔══██╗██╔══██║██╔══██║╚════██║██╔═══╝ ██║███╗██║██║╚██╗██║██╔══╝  ██║  ██║    
███████║╚██████╔╝██████╔╝██║  ██║██║  ██║███████║██║     ╚███╔███╔╝██║ ╚████║███████╗██████╔╝    
╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝      ╚══╝╚══╝ ╚═╝  ╚═══╝╚══════╝╚═════╝     
    """
    print_colored_banner(banner)
    parser = argparse.ArgumentParser(description="Subdomain Takeover Checker")
    parser.add_argument("-f", "--file", help="Path to the file containing subdomains", required=True)
    parser.add_argument("-t", "--threads", help="Number of threads to use", type=int, default=5)
    args = parser.parse_args()
    
    with open('vulnerable.yaml', 'r') as f:
        vulnerable_services = yaml.safe_load(f)

    output_file = "takeover.txt"
    requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
    main(args.file, output_file, args.threads)
