# DNS-attack

## DNS attack through amplifing the DNS reponse
1. Use raw socket to generate UDP packets with spoofed IP addresses and sent it to a DNS server. The spoofed address is the IP address of the victim.
2. Each of the UDP packets makes a DNS query request to DNS server. Passing type of ANY and class of IN.
3. Use EDNS to receive the larger response.
4. The victim will receive lots of amplified DNS response.

## Solution
1. Block the port that would become attack target
2. Implementing Source IP Verification on a network device
3. Block packet come from known vulnerable DNS server
4. Limiting Recursion to Authorized Clients
5. Use Netflow or sFlow to monitor abnormal packets
