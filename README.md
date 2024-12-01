
# Email Document Analyzer with Threat Intelligence

## Project Overview

The **Email Document Analyzer** is a tool designed to analyze email files (`.eml`, `.msg`), extract vital information such as attachments, URLs, domains, IP addresses, and perform threat intelligence checks. It integrates with several threat intelligence platforms like VirusTotal, Phishtank, AbuseIPDB, and others to provide real-time insight into potential threats found in the email artifacts.

The tool supports extracting email metadata, identifying phishing attempts, analyzing attached files for malware, and checking IPs and URLs against threat intelligence databases.

## Key Features
- **Email parsing**: Extracts important data like email headers, attachments, URLs, and IP addresses.
- **Attachment analysis**: Scans email attachments for malware using VirusTotal and other platforms.
- **Threat intelligence**: Uses multiple APIs to detect malicious links, phishing attempts, and suspicious IP addresses.
- **Quick insights**: Provides a comprehensive report on potential threats.
- **YARA rules integration**: Detect known malware signatures.
- **Support for `.eml` and `.msg` formats**.

## Components

### 1. Email Parsing
- Extract metadata (sender, receiver, subject, date).
- Extract attachments (files, URLs, links).
- Extract headers and check for suspicious IP addresses.
  
### 2. Threat Intelligence APIs Integration
- **VirusTotal**: Scans files and URLs for malware and viruses.
- **Phishtank**: Checks URLs for phishing attacks.
- **AbuseIPDB**: Analyzes IP addresses to detect known malicious activity.
- **URLHaus**: Detects URLs associated with known malware or botnets.
- **Hybrid Analysis**: In-depth analysis of suspicious files in a sandbox environment.

### 3. File and Document Analysis
- Extract and analyze text from PDFs or Office documents attached in the email.
- Support for analyzing `.doc`, `.pdf`, `.xls` files.

### 4. YARA Rule Integration
- Apply custom YARA rules to attachments to detect specific malware patterns.

## Libraries and Tools

### 1. **Email Parsing Libraries**
- **`email`** (Python Standard Library)
  - Parses `.eml` files to extract metadata, headers, and attachments.
  - [Documentation](https://docs.python.org/3/library/email.html)
  
- **`extract_msg`**
  - Extracts metadata, body, and attachments from `.msg` files (Outlook format).
  - [Extract MSG GitHub](https://github.com/mattgwwalker/msg-extractor)

- **`eml-parser`**
  - Extracts attachments, embedded files, and metadata from `.eml` files.
  - [Eml Parser GitHub](https://github.com/karastojko/eml-parser)

### 2. **Threat Intelligence APIs**
- **VirusTotal API**
  - Scans files and URLs for malware. 
  - [VirusTotal API Docs](https://developers.virustotal.com/)

- **Phishtank API**
  - Detects phishing URLs.
  - [Phishtank API Docs](https://www.phishtank.com/developer_info.php)

- **AbuseIPDB API**
  - Checks IP addresses for known malicious activity.
  - [AbuseIPDB API Docs](https://www.abuseipdb.com/api)

- **URLHaus API**
  - Detects URLs involved in malware or command-and-control operations.
  - [URLHaus API Docs](https://urlhaus-api.abuse.ch/)

- **Hybrid Analysis API**
  - Provides sandbox analysis of suspicious files and URLs.
  - [Hybrid Analysis API Docs](https://www.hybrid-analysis.com/docs/api/v2)

### 3. **Python Libraries for API Integration**
- **`virustotal-python`**
  - A wrapper for interacting with the VirusTotal API.
  - [VirusTotal Python](https://github.com/Xen0ph0n/virustotal-python)

- **`requests`**
  - A simple HTTP library to make API requests.
  - [Requests Docs](https://docs.python-requests.org/en/latest/)

### 4. **IP and URL Analysis**
- **`ipwhois`**
  - Queries IP addresses for ownership and geographical information.
  - [IPWhois Library](https://pypi.org/project/ipwhois/)

- **`abuseipdb-python`**
  - A Python wrapper for AbuseIPDB to check for malicious IP addresses.
  - [AbuseIPDB Python](https://pypi.org/project/abuseipdb-python/)

### 5. **HTML Parsing for URLs in Emails**
- **`BeautifulSoup`**
  - Parses HTML content to extract URLs from HTML-based emails.
  - [BeautifulSoup Docs](https://www.crummy.com/software/BeautifulSoup/)

### 6. **PDF and Document Analysis**
- **`pdfminer`** or **`PyPDF2`**
  - Extracts text and metadata from PDF documents.
  - [PDFMiner](https://pypi.org/project/pdfminer/)
  - [PyPDF2](https://pypi.org/project/PyPDF2/)

- **`olefile`**
  - Analyzes Microsoft Office files to extract metadata.
  - [OleFile Library](https://github.com/decalage2/olefile)

### 7. **YARA Integration**
- **YARA**
  - Detects patterns associated with malware using custom rules.
  - [YARA Docs](https://yara.readthedocs.io/en/stable/)

### 8. **MISP Integration**
- **PyMISP**
  - Interacts with the MISP threat intelligence platform to gather additional threat data.
  - [PyMISP GitHub](https://github.com/MISP/PyMISP)

## Project Structure

```bash
email_analyzer/
│
├── main.py               # Entry point of the application
├── requirements.txt      # Required libraries
├── README.md             # Project documentation
├── parsers/              # Email parsing components
│   ├── eml_parser.py
│   ├── msg_parser.py
│
├── analysis/             # Threat intelligence components
│   ├── virustotal.py
│   ├── abuseipdb.py
│   ├── phishtank.py
│
├── utils/                # Utility functions
│   ├── file_analysis.py  # File analysis tools (PDFs, Office docs)
│   ├── ip_analysis.py    # IP address analysis
│   ├── yara_analysis.py  # YARA rule integration
│
└── reports/              # Generates reports of analysis
    └── report_generator.py
```

## Setup Instructions

1. Clone the repository:
   ```bash
   git clone https://github.com/ethic-bakeery/email_analyzer.git
   cd email_analyzer
   ```

2. Install required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Set up your API keys:
   - Obtain API keys for VirusTotal, AbuseIPDB, Phishtank, and others, and store them in an environment file `.env`.

4. Run the application:
   ```bash
   python3 main.py
   ```
   
