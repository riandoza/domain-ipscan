# Domain IPs CIDR Scan

This process helps identify potential vulnerabilities and misconfigurations within a network based on the IP addresses used by a domain.

Scans a list of IP or domains and their corresponding IP addresses to check if they are not in cloudflare's network.

```
python main.py -i input.csv
```

Result of this command will be saved in the `./data/output.csv` file.
Also, you can use the following command to remove duplicate lines from a CSV file:

```
python main.py -d /data/output.csv
```

For filtering the CSV file by a column and value, you can use the following command:

```
python main.py -f ./data/output.csv filter dns==normal
python main.py -f ./data/output.csv filter dns==normal cidr==104.21.79
```

The syntax after filter separate by space. The first argument is the column name and the second one is the value to filter by. We use the `contains` filter.
The output of this command will be saved in the `./data/output_filtered.csv` file.

You can check open port 80 on CIDR range using this script:

```
python main.py -c 192.168.1.0/24
```
