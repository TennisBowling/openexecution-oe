## WARNING: DO NOT USE THIS CODE
This code is not maintained, and cannot follow mainnet.  
Use the new [openexecution](https://github.com/tennisbowling/openexecution).

## openexecution-oe
Software that lets you use 1 EL : multiple CL's

# How to build:
Clone the repo with
```
git clone https://github.com/TennisBowling/openexecution-oe
```
Enter the folder with
```
cd openexecution-oe
```  

And then run this on OS' with `make` (linux, etc):  
```
make build
```
and for windows:  
```
cargo build --profile highperf
```
Which will build the `openexecution-oe` program at
`bin/highperf/openexecution-oe`

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
        --unauth-node <unauth_node>    unauth EL node to connect to (for non-engine_ requests, such as eth_ requests)
```
Everything that does not have a default is required.  
Example:  
```
bin/highperf/openexecution-oe --port 5588 --jwt-secret /etc/jwt --unauth-node http://127.0.0.1:8545 --node http://127.0.0.1:8551 --db-host 127.0.0.1 --db-name openexecutiondatabase --db-pass databasepassword --db-port 5432 --db-user openexecution
```  

# How to use
Now, just point any CL to the endpoint of OE, and profit.  
Ex.  
If your running OE with --port 5588, you would pass this to the CL:  
http://[address]:5588  

For the jwt secret, you can generate a random jwt secret with



For your controlling CL, simply use the canonical (/canonical) endpoint of OE. The jwt must be the same for OE as for the EL and CL  
Ex.  
For your controlling CL, pass this as the execution endpoint:  
http://[address]:5588/canonical
