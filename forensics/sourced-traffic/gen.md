Instructions for generating the artifacts for this challenge

Setup:
1. Set up 2 hosts that can communicate with each other (2 ec2 instances, a host machine and a VM, literally any 2 devices that can run python)
2. Copy `client.py` to one host (hereafter referred to as the client) and copy `server.py` to the other host (hereafter referred to as the server)
3. The scripts depend on pyCryptodome, so `python3 -m pip install pyCryptodome` if it is not on the hosts.
4. Modify client script to connect to server's IP. Hide client in whatever way is cool.

Acquiring the pcap:
1. Run tcpdump on client, `tcpdump -i eth0 -w capture.pcap host <IP>`, where `<IP>` is the server's IP
2. Run server, then run client.
3. Execute whatever garbage commands you want, at some point execute a command containing the flag (e.g. `echo gigem{s1mpl3_tr4ff1c_d3crypt10n}`)
4. Acquire pcap from client.

Acquiring the image:
Just dd if you know how, this walks through getting the image from an ec2 instance.
Note that you should make sure the server has enough space to copy the entire memory of the client to it, otherwise you'll run into memory issues.
1. On the server, run `nc -l 19000|bzip2 -d|dd bs=16M of=./disk.img`
2. On the client, run `dd bs=16M if=<DEV>|bzip2 -c|nc <IP> 19000`, where `<DEV>` is the device you want to copy over, and `<IP>` is the server's IP
    - If you don't know what device to copy, run `df -h` and look for the one that is mounted on `/`
3. Compress it or whatever and copy it down via ssh.
