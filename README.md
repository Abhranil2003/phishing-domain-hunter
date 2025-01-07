# Phising DomainHunter

DomainHunter is a Python-based tool designed to assist penetration testers and Red Team operators in identifying expired or available domains suitable for phishing or Command-and-Control (C2) infrastructure. The tool integrates multiple domain reputation services to assess the credibility of domains and provides actionable outputs.

## Key Features

- **Domain Search**: Retrieves recently expired or deleted domains (".com", ".net", ".org") from ExpiredDomains.net.
  - Requires ExpiredDomains.net credentials for full functionality.
  
- **Reputation Analysis**: Performs domain reputation checks using services such as:
  - Symantec Site Review (BlueCoat)
  - IBM X-Force
  - Cisco Talos
  - McAfee Web Gateway
  
- **Sorting and Filtering**: Allows sorting by domain age and filters based on reputation results.

- **Output Formats**: Generates text-based tables or HTML reports with detailed domain information.

- **Optional CAPTCHA Handling**: Supports Optical Character Recognition (OCR) for CAPTCHA challenges.

- **Flexible Queries**: Supports keyword-based searches, single domain analysis, and bulk file inputs.

## Installation

### Prerequisites

-Python 3.7 or higher
-Recommended libraries (install via requirements.txt):
    
    pip3 install -r requirements.txt
    
-Optional OCR dependencies for CAPTCHA support:
-Debian/Ubuntu:

        apt-get install tesseract-ocr python3-pil
-macOS:

        brew install tesseract
    
### Using pipenv

1. Install pipenv:

        pip install pipenv

2. Set up the environment:

       pipenv --python 3.7
       pipenv install

### Using Docker

1. Build the Docker image:

       docker build -t domainhunter

2. Run the container:

       docker run -it domainhunter [arguments]

### Usage

#### Basic Usage
To retrieve the most recent 100 expired domains and perform reputation checks:

        python3 domainhunter.py

#### Common Options
-Search for domains containing a specific keyword:

        python3 domainhunter.py -k <keyword> -r <max_results> -c

-Perform a detailed check for a single domain:

        python3 domainhunter.py -s <domain>

-Analyze domains from a file:

        python3 domainhunter.py -f <file_path> -c

-Adjust timing to avoid CAPTCHA challenges:

        python3 domainhunter.py -t <0-5>
        
#### Help
For the full list of options, use:

        python3 domainhunter.py --help

#### Examples
1. Search for 1000 expired domains related to "tech" and check their reputations:

       python3 domainhunter.py -k tech -r 1000 -c

2. Perform reputation checks for domains listed in domains.txt with OCR for CAPTCHA challenges:

       python3 domainhunter.py -f domains.txt --ocr

3. Generate a quick report for "mydomain.com":

       python3 domainhunter.py -s mydomain.com
   
### Output

DomainHunter generates:
    1. Console Output: Text-based tables with domain details and reputations.
    2.HTML Reports: Richly formatted reports with clickable links to additional domain details.

### Disclaimer

*This tool is intended for educational and ethical purposes only. Users are responsible for ensuring compliance with applicable laws and regulations. Misuse of this tool is strictly prohibited.*
