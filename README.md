# Domain IPs CIDR Scan

This process helps identify potential vulnerabilities and misconfigurations within a network based on the IP addresses used by a domain.

Before running this script make sure to install all the required dependencies using the following command:

`pip install -r requirements.txt`

## Available Tools

- [x] Cloudflare domain scan (`cf`)
- [x] CIDR scan open port (`cidr`)
- [x] Get IP Country Code (`ip2cc`)
- [x] Filtering CSV file (`filter`)
- [x] Duplicate Removal (`duplicate`)

## Usage

Scans a list of IP or domains and their corresponding IP addresses to check if they are not in cloudflare's network.

```
python main.py cf --help
python main.py cf --input ./domains.txt  -o ./cf_ips.csv
```

Result of this command will be saved in the `./cf_ips.csv` file.
Also, you can use the following command to remove duplicate lines from a CSV file:

```
python main.py duplicate --help
python main.py duplicate --input ./cf_ips.csv
python main.py duplicate --input ./cf_ips.csv --output ./cf_ips_cleared.csv
```

For filtering the CSV file by a column and value, you can use the following command:

```
python main.py filter --help
python main.py filter --input ./cf_ips.csv  -o ./filtered.csv -c dns==normal
python main.py filter --input ./cf_ips.csv  -o ./filtered.csv -c dns==normal cidr==104.21.79
```

The syntax after filter separate by space. The first argument is the column name and the second one is the value to filter by. We use the `contains` filter.
The output of this command will be saved in the `./filtered.csv` file.

You can check open port 80 on CIDR range using this script:

```
python main.py cidr --help
python main.py cidr --ips 192.168.1.0/24 --port 80 --output ./open_ports.csv
```

To determine the country code (CC) associated with an IP address, you can use the following command:

```
python main.py ip2cc --help
python main.py ip2cc --input ips.txt --output ips_with_cc.csv

# Filtering only the country code (CC) associated with an IP address:
python main.py ip2cc --input ips.txt --output ips_with_cc.csv --filter US,SG
```

The output of this command will be saved in the `./ips_with_cc.csv` file. You can use it to filter by country code (CC) and save only the IP addresses associated with that country code. Filtering separate by comma
See available [country codes](https://www.iban.com/country-codes)
