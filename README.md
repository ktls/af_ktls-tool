# Linux Kernel TLS/DTLS Socket Tool

*Note that the implementation is under heavy development. Use on your own risk!*

This tool is demonstrating usage, benchmarking and verifying the implementation
of [AF_KTLS socket](https://github.com/fridex/af_ktls/).

This tool consists of two parts - a client and a server. You can run server as
a standalone process or you can run the server in a separate thread. Note that
benchmarks use ```clock(3)``` to determine processor time, so you will be
benchmarking server as well when run in a thread.

The implementation is using Gnu TLS now. ```AF_KTLS``` currently support only
AES GCM, but Gnu TLS and OpenSSL are sharing code for AES GCM cipher.

Consider dropping caches by ```--drop-caches``` before each run to omit kernel
caching impact.

## Scenarios

There are two types of benchmarks:
  * ```*-count COUNT``` to send (and receive) specified number of records
  * ```*-time SECS``` to run scenario specified amount of time

You can specify MTU by:
  * ```--payload``` to specify payload for ```send(2), recv(2)``` and
  	 ```splice(2)``` when ```AF_KTLS``` is destination socket
  * ```--sendfile-mtu``` to specify MTU when benchmarking ```sendfile(2)```  and
  	 ```splice(2)``` when ```AF_KTLS``` socket is destination socket
  	 (```sendpage()``` is called in the kernel)

To evaluate speed impact, there were designed following scenarios:

### Send

This scenario can be run by supplying ```--send-{gnutls,ktls}-{time,count}```.
In this case you will test Gnu TLS and ```AF_KTLS``` sending and receiving (if
compiled with ```BENCHMARK_RECV``` defined) - to be more concrete ```send(2)```
and ```recv(2)``` calls.


### Splice

By supplying ```--splice-{count,time}``` you can splice a file (by default
```/dev/zero``` is used to omit hard disk drive and file system impact.
A content is read from a file, written to a pipe and transmitted from pipe to
a ```AF_KTLS``` socket.

### Splice Echo

This scenario can be run by supplying ```--splice-echo-{time,count}```. This
scenario uses ```splice(2)``` to read from ```AF_KTLS``` socket, write to
a pipe,  read from a pipe and write to ```AF_KTLS``` socket again.

### Send a File

You can send a file using ```sendfile(2)``` or you can do ```recv(2)```
- encrypt in userspace -- ```send(2)```. For benchmarking ```sendfile(2)```
supply ```--sendfile FILE```, for use space encryption, supply ```--sendfile-buf
FILE```. If you want to specify MTU, for ```sendfile(2)```, specify
```--sendfile-mtu MTU```, for user space encryption, you have to adjust payload
by ```--payload BYTES```. Please note that ```AF_KTLS``` is computing MTU with
TLS/DTLS overhead. That means that if you supply MTU 1400 for a TLS, the data
carried within one packet will be 1400 - sizeof(tls_overhead) (1400 - 5 (header)
- 8 (iv) - 16(tag) for TLS and 1400 - 13 (header) - 8(iv) - 16(tag)).

## Verifying Implementation

There is implemented a test suite. You can access it by supplying
```--verify-sendpage``` (```sendpage()``` implmenetation in the kernel),
```--verify-transmission``` (```send(2)``` and ```recv(2)```),
```--verify-splice-read``` (```splice_read()``` implementation in the kernel)
and ```--verify-handling``` (```getsockopt(2)```, ```setsockopt(2)``` and basic
socket operatiosn).

## Help

To see all available options, see ```--help```. Feel free to visit
[issues](https://github.com/fridex/af_ktls-tool/issues) page as well.

See also [AF_KTLS](https://github.com/fridex/af_ktls), [AF_KTLS
visualize](https://github.com/fridex/af_ktls-visualize).

