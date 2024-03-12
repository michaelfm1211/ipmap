# ipmap
ipmap lets you mass-send ping packets to every host on a subnet then saves a
bitmap of whether or not each host responded to a file. ipmap will skip over
reserved IP blocks and only works with IPv4.

For example, to scan every host on the subnet 1.0.0.0/8 just run
```
sudo ipmap 1.0.0.0/8 results
```
The results will be written to `results`.

**Note**: `ipmap` uses raw sockets, so you must run the command as root.

To see results from a scan, you can use the `ipmap-query` tool. For example, to
check the status of 1.1.1.1 from the previous scan, you can use
```
ipmap-query results 1.1.1.1
```
or, to get the statuses of the entire 1.1.1.0/24 subnet, you can use
```
ipmap-query results 1.1.1.0/24
```
