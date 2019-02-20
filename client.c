#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT "8096"
#define MSG_LEN 256
#define NAME_LEN 8
#define TIME_LEN 9

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*) sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

int main(int argc, char *argv[]) {
  int status;
  struct addrinfo hints, *res, *p;
  int sock_fd;
  char message[MSG_LEN];
  char client_ip[INET6_ADDRSTRLEN];
  char name[NAME_LEN];
  char timestamp[TIME_LEN];

  if (argc != 2) {
    fprintf(stderr, "usage: client hostname\n");
    exit(1);
  }

  /* set up structs */
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE; 	/* use my IP */

  if ((status = getaddrinfo(argv[1], PORT, &hints, &res)) != 0) {
    fprintf(stderr, "get addrinfo error: %s\n", gai_strerror(status));
    exit(1);
  }

  /* bind to the first actual result */
  for (p = res; p != NULL; p = p->ai_next) {
    if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if (connect(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sock_fd);
      perror("client: bind");
      exit(1);
    }

    break;
  }

  if (!p) {
    fprintf(stderr, "client: failed to bind\n");
    exit(1);
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), client_ip, sizeof client_ip);
  printf("client: connecting to %s\n", client_ip);

  /* finished setting up socket */
  freeaddrinfo(res);

  /* send name */
  gethostname(name, NAME_LEN); // check for errors?
  if (send(sock_fd, name, strlen(name), 0) == -1) {}

  while(1) {
    printf("> ");
    fgets(message, MSG_LEN, stdin); 

    /* ignore empty messages */
    while (message[0] == '\n') {
      printf("\e[1A");
      printf("> ");
      fgets(message, MSG_LEN, stdin); 
    }

    send(sock_fd, message, strlen(message), 0);

    while (recv(sock_fd, timestamp, TIME_LEN, 0) > 0) {
      printf("\e[1A\e[K");
      printf("[%s] %s: %s", timestamp, name, message);
      break;
    }

    /* breaking condition? */
  }

  close(sock_fd);

  return 0;
}
