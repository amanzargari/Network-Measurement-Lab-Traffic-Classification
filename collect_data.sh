#!/bin/bash

WEBSITES="https://www.theguardian.com https://www.finance.yahoo.com https://www.indiatimes.com https://www.washingtonpost.com https://www.rt.com https://www.express.co.uk https://www.cnbc.com https://www.abc.net.au https://www.nytimes.com https://www.nypost.com"

# Filter to capture only HTTPS traffic while excluding internal traffic between devices on the same network
FILTER="not (src net 172.16.0.0/12 && dst net 172.16.0.0/12) && tcp port 443"

# Automatically select the first available network interface that matches common patterns for Ethernet and Wi-Fi interfaces
INTERFACE=$(tshark -D | grep -E "en|eth|wlan|wi-fi|wifi" | head -n 1 | cut -d. -f1)
echo "Using network interface: ${INTERFACE}"

mkdir -p ./Captured_Data

# Loop through each website and capture traffic for 10 requests
for site in $WEBSITES; do

    # Extract the domain name from the URL for naming the output files
    domain=$(echo $site | awk -F/ '{print $3}')
    echo "Starting capture for $domain..."

    for j in {1..10}; do

        # Start tshark in the background to capture traffic for the specified interface and filter, saving both pcap and CSV outputs
        tshark -i "${INTERFACE}" -T fields -E header=y -E separator=, -E occurrence=f -e frame.number -e frame.time -e ip.len -e ip.proto -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e tcp.len -f "${FILTER}" -w "./Captured_Data/${domain}_${j}.pcap" > "./Captured_Data/${domain}_${j}.csv" &
        RUNNING_PID=$!

        sleep 2

        echo "--- Request $j"

        # Use curl to make a request to the website, which will trigger the capture of the traffic. The output is discarded since we are only interested in the network traffic.
        curl -s "$site" > /dev/null

        sleep 6

        # After the request is made and some time is given for the traffic to be captured, we kill the tshark process to stop the capture for this request.
        kill ${RUNNING_PID}
        wait ${RUNNING_PID} 2>/dev/null
    done

    echo "Finished capturing $domain."
done

echo "All captures completed. Data saved in the 'Captured_Data' directory."