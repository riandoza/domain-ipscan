# Domain IPs CIDR Scan

This process helps identify potential vulnerabilities and misconfigurations within a network based on the IP addresses used by a domain.

Scans a list of IP or domains and their corresponding IP addresses to check if they are not in cloudflare's network.

```
python main.py -i input.csv
```

Result of this command will be saved in the `output.csv` file.
Also, you can use the following command to remove duplicate lines from a CSV file:

```
python main.py -d output.csv
```

You can check open port 80 on CIDR range using this script:

```
python main.py -c 192.168.1.0/24
```
