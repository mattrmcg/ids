### Introduction
So far, this project supports portscan detection. More will be added in the future.

Run `go build -o ids cmd/main.go` to build the executeable

**NOTE**: For the program to read raw packets from libpcap, it needs to either be ran with sudo or granted packet read and create privileges with `sudo setcap 'cap_net_raw+ep' ./path-to-the-executable`

When running, specify the network interface to listen on with the `-d` flag:
`./ids -d enp0s1`

You can test that it's working by running an nmap scan against the host
<img width="1620" height="462" alt="image" src="https://github.com/user-attachments/assets/533de030-c5f6-4127-8cfb-947a4e8f5b87" />

On your host machine, you should receive a json-formatted alert for the port scan
<img width="1809" height="573" alt="image" src="https://github.com/user-attachments/assets/e4da739d-2006-4917-9659-1e6b04dcb316" />

The program is built on top of libpcap and processes incoming packets concurrently. Packets get dropped sometimes due to libpcap's limitations, but any portscan with more than 60 or so scans in a 30 second window should get detected
