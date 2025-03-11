goarpwatch is a somewhat simplistic replacement for the arpwatch command.  It supports both arp and ipv6 NDP.

goarpwatch uses bolt to store ip / mac pairs.  The database is read into memory when goarpwatch starts and all operations are done from the in memory cache.

A few prometheus metrics are exported so you can see what's going on.
