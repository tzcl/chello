# chello
chello as in c-hello is a basic terminal chat application built to learn more about the sockets API and pthreads. Inspired by [Beej's Guide to Network Programming](https://beej.us/guide/bgnet/html/multi/index.html).

## Build

**server.c**
```
gcc -o server server.c
```
**client.c**
```
gcc -pthread -o client client.c
```

## Usage

```
./server
./client <server-ip>
```
![Screenshot](https://i.imgur.com/bR430oT.png)
