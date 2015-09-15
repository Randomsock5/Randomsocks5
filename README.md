Randomsocks5
======

Plan B in case of emergency

Use:
======

```bash
#./rs-server  -addr [Server Addre] -passwd [*********]  -port xxx
#./rs-server --help
Usage of ./rs-server:
  -addr string
    	Set Listen Addr
  -passwd string
    	Set Passwd (default "hello world")
  -port int
    	Set Server Port (default 9500)

#./rs-client --help
Usage of ./rs-client:
  -local string
    	Set Local Addr (default "127.0.0.1")
  -lport int
    	Set Local Port (default 9500)
  -passwd string
    	Set Passwd (default "hello world")
  -server string
    	Set Server Addr (default "127.0.0.2")
  -sport int
    	Set Server Port (default 9500)
        
```
