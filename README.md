# Phising Domain Hunter

Selecting domain names is a crucial part of preparing for penetration tests, particularly during Red Team operations. Often, domains that were previously utilized for harmless purposes and were accurately classified can be acquired for just a few dollars. Such domains enable teams to bypass reputation-based web filters and network egress limitations for phishing and command-and-control (C2) related activities.
This tool, developed in Python, is designed to swiftly query the Expireddomains.net search engine for expired or available domains that have a prior usage history. It can also optionally check the domain's reputation against services such as Symantec Site Review (BlueCoat), IBM X-Force, and Cisco Talos. The main output of the tool is a timestamped HTML report formatted as a table.

## Features

-Fetch a specified number of recently expired and deleted domains (.com, .net, .org) from ExpiredDomains.net.
-Note: Credentials from expireddomains.net are required for full functionality.
-Retrieve available domains based on keyword searches from ExpiredDomains.net.
-Conduct reputation checks against Symantec WebPulse Site Review (BlueCoat), IBM X-Force, and Cisco Talos.
-Organize results by domain age (if known) and filter based on reputation.
-Output includes a text-based table and HTML report with links to reputation sources and Archive.org entries.

## Installation

### Direct Installation

Install the necessary Python packages:

    pip3 install -r requirements.txt
    
Optional - Install additional dependencies for OCR support:

- Debian/Ubuntu: `apt-get install tesseract-ocr python3-pil`

- MAC OS: `brew install tesseract`

### pipenv installation

    pipenv --python 3.7
    pipenv install

Optional -  Install additional dependencies for OCR support:

- Debian/Ubuntu: `apt-get install tesseract-ocr python3-pil`

### Docker

1. Build the Docker image:
`docker build -t domainhunter .`

2. Run it with your specified arguments:
`docker run -it domainhunter [args]`

## Usage
 Usage Syntax:
    domainhunter.py [-h] [-a] [-k KEYWORD] [-c] [-f FILENAME] [--ocr] [-r MAXRESULTS] [-s SINGLE] [-t {0,1,2,3,4,5}] [-w MAXWIDTH] [-V]


This tool identifies expired domains, categorizes them, and checks Archive.org history to find suitable candidates for C2 and phishing operations.
    optional arguments:
    -h, --help            Display this help message and exit.
    -a, --alexa           Filter results to include only Alexa listings.
    -k KEYWORD, --keyword KEYWORD
                            Keyword used to narrow search results.
    -c, --check           Conduct domain reputation checks.
    -f FILENAME, --filename FILENAME
                            Specify an input file containing line-separated domain names to check.
    --ocr                 Perform OCR on CAPTCHAs when encountered.
    -r MAXRESULTS, --maxresults MAXRESULTS
                            Number of results to return when querying the latest expired/deleted domains.
    -s SINGLE, --single SINGLE
                            Conduct detailed reputation checks against a single domain name/IP.
    -t {0,1,2,3,4,5}, --timing {0,1,2,3,4,5}
                            Adjust request timing to avoid CAPTCHAs. Slowest (0) = 90–120 seconds; 
                            Default (3) = 10–20 seconds; 
                            Fastest (5) = no delay.
    -w MAXWIDTH, --maxwidth MAXWIDTH
                            Set the width of the text table.
    -V, --version         Display the program's version number and exit.

Examples:

    ./domainhunter.py -k apples -c --ocr -t5
    ./domainhunter.py --check --ocr -t3
    ./domainhunter.py --single mydomain.com
    ./domainhunter.py --keyword tech --check --ocr --timing 5 --alexa
    ./domaihunter.py --filename inputlist.txt --ocr --timing 5

Use defaults to check the most recent 100 domains and verify their reputation:
    
    python3 ./domainhunter.py

Search for 1000 most recently expired/deleted domains without checking their reputation:

    python3 ./domainhunter.py -r 1000

Conduct all reputation checks for a specific domain:

    python3 ./domainhunter.py -s mydomain.com

    [*] Downloading malware domain list from http://mirror1.malwaredomains.com/files/justdomains
    [*] Fetching domain reputation for: mydomain.com
    [*] BlueCoat: mydomain.com
    [+] mydomain.com: Technology/Internet
    [*] IBM xForce: mydomain.com
    [+] mydomain.com: Communication Services, Software as a Service, Cloud (Score: 1)
    [*] Cisco Talos: mydomain.com
    [+] mydomain.com: Web Hosting (Score: Neutral)


Execute all reputation checks for a list of domains at maximum speed with OCR on CAPTCHAs:

    python3 ./domainhunter.py -f <domainslist.txt> -t 5 --ocr

Search for available domains with the keyword "dog", limiting results to 25 while checking their reputation:
    
    python3 ./domainhunter.py -k dog -r 25 -c

     ____   ___  __  __    _    ___ _   _    _   _ _   _ _   _ _____ _____ ____
    |  _ \ / _ \|  \/  |  / \  |_ _| \ | |  | | | | | | | \ | |_   _| ____|  _ \
    | | | | | | | |\/| | / _ \  | ||  \| |  | |_| | | | |  \| | | | |  _| | |_) |
    | |_| | |_| | |  | |/ ___ \ | || |\  |  |  _  | |_| | |\  | | | | |___|  _ <
    |____/ \___/|_|  |_/_/   \_\___|_| \_|  |_| |_|\___/|_| \_| |_| |_____|_| \_\

    Expired Domains Reputation Checker
    
    DISCLAIMER: This tool is intended solely for educational purposes!
    It aims to foster learning and enhance computer/cybersecurity practices.
    
    The author or his employer bear no responsibility for any unlawful actions or misuse by users of this tool. 
    If you intend to use this content for illegal activities, please refrain from doing so.
    Have a great day! :)

    [*] Downloading malware domain list from http://mirror1.malwaredomains.com/files/justdomains

    [*] Retrieving expired or deleted domains containing "dog"
    [*] https://www.expireddomains.net/domain-name-search/?q=dog
    [*] Executing domain reputation checks for 8 domains.
    [*] BlueCoat: doginmysuitcase.com
    [+] doginmysuitcase.com: Travel
    [*] IBM xForce: doginmysuitcase.com
    [+] doginmysuitcase.com: Not found.
    [*] Cisco Talos: doginmysuitcase.com
    [+] doginmysuitcase.com: Uncategorized
