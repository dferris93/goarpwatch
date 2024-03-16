goarpwatch is a somewhat simplistic replacement for the arpwatch command.  

goarpwatch uses sqlite3 to store ip / mac pairs, although the real work is done with a simple map[sting]string.

A few prometheus metrics are exported so you can see what's going on.
