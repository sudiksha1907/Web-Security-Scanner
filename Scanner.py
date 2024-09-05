import requests
from bs4 import BeautifulSoup
import subprocess
from urllib.parse import urljoin
from fpdf import FPDF
import concurrent.futures
import sqlmap
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def crawl_website(url):
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
    except requests.exceptions.RequestException as e:
        logging.error(f"Error crawling website: {e}")
        return []
    soup = BeautifulSoup(response.text, 'html.parser')
    links = []
    for a in soup.find_all('a', href=True):
        href = a['href']
        if href.startswith('/'):  # relative URL
            href = urljoin(url, href)
        if not href.startswith('http'):  # not a fully qualified URL
            continue
        links.append(href)
    return links

def scan_link(link):
    try:
        response = requests.get(link)
        if response.status_code != 200:
            return {link: []}  # Skip links with non-200 status codes
    except requests.exceptions.RequestException:
        logging.error(f"Error scanning link: {link}")
        return {link: []}  # Skip links with request exceptions
    vulnerabilities = []
    try:
        # Scan for SQL injection
        sqlmap_command = f"sqlmap -u '{link}' --batch --random-agent --level 3 --risk 3"
        output = subprocess.check_output(sqlmap_command, shell=True)
        if b"vulnerable" in output:
            vulnerabilities.append("Potential SQL injection vulnerability")
    except subprocess.CalledProcessError:
        pass
    except Exception as e:
        logging.error(f"Error scanning link: {link} - {e}")
    # Scan for XSS
    try:
        xss_payload = "<script>alert(1)</script>"
        response = requests.get(link, params={'xss': xss_payload})
        if xss_payload in response.text:
            vulnerabilities.append("Potential XSS vulnerability")
    except requests.exceptions.RequestException:
        pass
    # Check for reflected XSS
    try:
        xss_reflected_payload = "<script>alert(document.cookie)</script>"
        response = requests.get(link, params={'xss_reflected': xss_reflected_payload})
        if xss_reflected_payload in response.text:
            vulnerabilities.append("Potential reflected XSS vulnerability")
    except requests.exceptions.RequestException:
        pass
    # Check for stored XSS
    try:
        xss_stored_payload = "<script>alert(1)</script>"
        response = requests.post(link, data={'xss_stored': xss_stored_payload})
        if xss_stored_payload in response.text:
            vulnerabilities.append("Potential stored XSS vulnerability")
    except requests.exceptions.RequestException:
        pass
    # Scan for authentication bypass
    try:
        auth_bypass_payload = {'username': 'admin', 'password': 'password'}
        response = requests.post(link, data=auth_bypass_payload)
        if response.status_code == 200 and "Welcome" in response.text:
            vulnerabilities.append("Potential authentication bypass vulnerability")
    except requests.exceptions.RequestException:
        pass
    # Scan for IDOR
    try:
        idor_payload = {'id': '1'}
        response = requests.get(link, params=idor_payload)
        if response.status_code == 200 and "sensitive information" in response.text:
            vulnerabilities.append("Potential IDOR vulnerability")
    except requests.exceptions.RequestException:
        pass
    # Scan for CSRF
    try:
        csrf_payload = {'csrf_token': 'invalid-token'}
        response = requests.post(link, data=csrf_payload)
        if response.status_code == 200 and "success" in response.text:
            vulnerabilities.append("Potential CSRF vulnerability")
    except requests.exceptions.RequestException:
        pass
    # Scan for CLI
    try:
        cli_payload = {'cmd': 'whoami'}
        response = requests.get(link, params=cli_payload)
        if response.status_code == 200 and "success" in response.text:
            vulnerabilities.append("Potential CLI vulnerability")
    except requests.exceptions.RequestException:
        pass
    return {link: vulnerabilities}

def scan_website(url):
    links = crawl_website(url)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        futures = [executor.submit(scan_link, link) for link in links]
        vulnerabilities = []
        for future in concurrent.futures.as_completed(futures):
            link_vulnerabilities = future.result()
            for link, vulns in link_vulnerabilities.items():
                if vulns:
                    vulnerabilities.append((link, vulns))  # Corrected this line
    return vulnerabilities

def generate_pdf_report(vulnerabilities, url):
    filename = f"vulnerability_report_{url.replace('://', '_').replace('/', '_')}.pdf"
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=15)
    pdf.cell(200, 10, txt=f"Vulnerability Report for {url}", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("Arial", size=12)
    for link, vulns in vulnerabilities:
        pdf.cell(200, 10, txt=f"URL: {link}", ln=True)
        for vuln in vulns:
            pdf.cell(200, 10, txt=f"  - {vuln}", ln=True)
        pdf.ln(5)
    pdf.output(filename)
    return filename  # Return the filename


def main():
    url = input("Enter URL to scan: ")
    if not url.startswith("http://") and not url.startswith("https://"):
        url = f"http://{url}"
    print(f"Scanning {url}...")
    vulnerabilities = scan_website(url)
    print("Scan complete. Generating report...")
    filename = generate_pdf_report(vulnerabilities, url)  # Get the filename
    print(f"Report saved as {filename}")
    print("Scan complete.")


if __name__ == "__main__":
    main()
