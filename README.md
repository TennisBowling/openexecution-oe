# openexecution-oe
Software that lets you use 1 EL : multiple CL's

# How to build:
Clone, and then run:
```
make build
```
on OS' with `make`, and on windows:
```
cargo build --profile highperf
```

# How to run:
You'll need a postgreSQL db.  
  
Then see these arguments for running:  
```
        --db-host <DB host>            Database host ip
        --db-name <DB name>            Database name
        --db-pass <DB pass>            Database password
        --db-port <DB port>            Database port
        --db-user <DB user>            Database user
        --jwt-secret <JWT>             Path to JWT secret file
        --listen-addr <LISTEN>         Address to listen on [default: 0.0.0.0]
        --log-file <log-path>          Path to log file
        --log-level <LOG>              Log level [default: info]
        --node <NODE>                  EL node to connect to for engine_ requests
        --port <PORT>                  Port to listen on [default: 7000]
        --unauth-node <unauth_node>    unauth EL node to connect to (for non-engine_ requests)
```
Everything that does not have a default is required.  

# How to use
Now, just point any CL to the endpoint of OE, and profit.  
Ex.  
If your running OE with --port 1234, you would pass this to the CL:  
http://[address]:1234  

Pass any jwt to the client CL it does not matter.

For your controlling CL, simply use the canonical (/canonical) endpoint of OE. The jwt must be the same for OE as for the EL and CL  
Ex.  
For your controlling CL, pass this as the execution endpoint:  
http://[address]:1234/canonical
