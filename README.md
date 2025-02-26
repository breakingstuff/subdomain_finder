# Phoenix Subdomain Enumeration Tool

Phoenix is a powerful and efficient subdomain enumeration tool designed to help security researchers and developers discover subdomains associated with a target domain. It leverages concurrent threading for fast and reliable subdomain discovery, and provides detailed information about each subdomain, including server types, HTTP headers, and optional port scanning and keyword filtering.

## Features

* **Fast Subdomain Enumeration:** Utilizes concurrent threads for rapid subdomain discovery.
* **Detailed Information:** Provides IP addresses, server types, and comprehensive HTTP headers for each subdomain.
* **Port Scanning (Optional):** Checks for open ports on discovered subdomains, allowing for deeper analysis.
* **Header Keyword Filtering (Optional):** Filters subdomains based on keywords found in HTTP headers.
* **Clean and Readable Output:** Presents results in a well-organized and easy-to-understand format.
* **JSON Output (Optional):** Outputs results in JSON format for easy integration with other tools.
* **Wordlist Included:** Comes with a growing wordlist of 602 words to enhance subdomain discovery.
* **Time and Subdomain Count:** Displays the execution time and the number of subdomains found.

## Usage

```bash
python3 phoenix.py -d <domain> -w <wordlist_path> [options]

Options
-d, --domain: Target domain (e.g., microsoft.com). (Required)
-w, --wordlist: Path to the wordlist file. (Required)
-o, --output: Path to output file (optional).
-j, --json: Output results in JSON format.
-v, --verbose: Enable verbose output (show headers).
-p, --ports: Check for open ports (e.g., 80 443).
-k, --keyword: Filter subdomains by keyword in headers.

Example

python3 phoenix.py -d microsoft.com -w wordlist.txt -v -p 80 443 -k "Microsoft-IIS"

This example will enumerate subdomains for hilton.com using wordlist.txt, display verbose output including headers, check for open ports 80 and 443, and filter subdomains that have "Microsoft-IIS" in their headers.

Installation

1. Clone the repository:

git clone https://github.com/breakingstuff/subdomain_finder/tree/main
cd phoenix

2. Install the required dependencies:

pip3 install dnspython requests urllib3

Contributing

Contributions are welcome! If you have any ideas for improvements, bug fixes, or new features, please feel free to submit a pull request.

Support My Work
If you find this tool helpful and would like to support its continued development, please consider making a donation. Your contributions help me dedicate more time to improving Phoenix and adding new features.

Crypto Donations:

Bitcoin (BTC): bc1qkv67jvr5ppzfc4hexh7azhx673830uvuhyc2qu

Ethereum (ETH): 0xBb1b01866b3349dB4a813a7E31df282f2D816E6F

Litecoin (LTC): ltc1q55hd6yhjwprhrcr966rrmqjnspvy3d6rhe45d8

Dash (DASH): XxeKjCeruXZKBVBJPh96gJHA9JWSCfY89v

Bitcoin Cash (BCH): qzuq23fwwr2rra3es6pwjqnj7qkf22ys4cj3zeu8kt

Polygon (MATIC): 0x9a08eCaE02D5801ff012bd0c9d65C8818625d295

Ravencoin (RVN): RXeNt2uPK4RvUvmdX8EFBS5X951KopZyFa

Solana (SOL): GAHKENfY8DZ6uDp3A8dQF1pqqSXMGRrVQnfsJzA6Tdqw

TON: UQA8d0_AinGKkGLdIS5Zrybh0uRyFDYRzNGbFrTA7fjgfiV_

SHIB (SHIB): 0xBb1b01866b3349dB4a813a7E31df282f2D816E6F

DOGE (DOGE): DNs1oeUxStHyQcCkmiqWZn65CtjSr6xooB

XRP (XRP): rhVruPkGYDYWfZxPqQyJXE8B75B1ogQBy6

FTC (Feathercoin): fc1qtvu07d68vmmzf9s40ppmme0z9ccwmewldecgaw

ADA (Cardano): addr1q9a5g6gsz2qdlc93gk03krswex28qx50taghy0lxgx7uej896q40zrygdm9j0m0qeugq3farmpc3684hfa9jv7jpyl9qqq784m

BNB (Binance Coin): 0xA5f6AF5A5E38992a9532D2d00818Fa29Ca0a1473

XMR (Monero): 49kcYHTZrwHWH6xHisUkqjK74HRecTiMNeakmVZn5oiSRgb2ocF4tG7CaZFjJocydYQcdRdBmkGhsKxCTT9pwr5c2TRtmXo

ZCash (ZEC): u1es765gl3plwd3xj9zw9fxy0qk54qm7xun37s2qtanzf8hzauphaasv4ftagf8gtm3vz4cs85sy7qnqalevwmp5pugrennm3p75cm3ep04u7gs4mr2yjn7s2x5euxxu6jgfqdjjk9yvr7ggj5mczeukmen707we9lhhrcpp93e935csclud6nkn65x6u406r7fgkg602erhhqjqhzht6

TRX (Tron): TJKwC7sSB9xXVuvuCwGk2oeFGgyBkL5gns

Thank you for your support!
