# ipmap
ipmap lets you mass-send ping packets to every host on a subnet then saves a
bitmap of whether or not each host responded to a file. ipmap will skip over
reserved IP blocks and only works with IPv4.

For example, to scan every host on the subnet 1.0.0.0/8 just run
```
ipmap 1.0.0.0/8 results
```
The resulting bit map will be written to `results`.

Note: `ipmap` uses raw sockets, so you must run the command as root.
