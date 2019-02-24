#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <ctype.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT "8096"
#define NAME_LEN 8
#define TIME_LEN 8
#define FORMAT_LEN 5
#define HEADER_LEN (NAME_LEN + TIME_LEN + FORMAT_LEN) 
#define PACKET_LEN 2048
#define MSG_LEN (PACKET_LEN - HEADER_LEN)
#define AEST (+10+1)		/* daylight savings */

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in*) sa)->sin_addr);
  }

  return &(((struct sockaddr_in6*) sa)->sin6_addr);
}

void get_time(time_t *rawtime, struct tm *time_data, char timestamp[]) {
  time(rawtime);
  time_data = gmtime(rawtime);
  snprintf(timestamp, TIME_LEN + 1, "%02d:%02d:%02d", (time_data->tm_hour + AEST) % 24, time_data->tm_min, time_data->tm_sec);
}

void init_socket(char server_address[], struct addrinfo *hints, int *sock_fd) {
  int status;
  struct addrinfo *res, *p;
  char server_ip[INET6_ADDRSTRLEN];

  if ((status = getaddrinfo(server_address, PORT, hints, &res)) != 0) {
    fprintf(stderr, "get addrinfo error: %s\n", gai_strerror(status));
    exit(1);
  }

  /* bind to the first actual result */
  for (p = res; p != NULL; p = p->ai_next) {
    if ((*sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("client: socket");
      continue;
    }

    if (connect(*sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(*sock_fd);
      perror("client: bind");
      exit(1);
    }

    break;
  }

  if (!p) {
    fprintf(stderr, "client: failed to bind\n");
    exit(1);
  }

  inet_ntop(p->ai_family, get_in_addr((struct sockaddr *)p->ai_addr), server_ip, sizeof server_ip);
  printf("client: connecting to %s\n", server_ip);

  freeaddrinfo(res);
}

char* clean_message(char* input) {
  char* dest = input;
  char* src = input;

  while (*src) {
    if (!isprint(*src)) {
      src++;
      continue; 
    }
    *dest++ = *src++;
  }
  *dest = '\0';
  return input;
}

void *listener_thread(void *sock_fd) {
  char packet[PACKET_LEN + 1] = {0};

  while(1) {
    memset(packet, 0, PACKET_LEN + 1);
    recv(*(int *)sock_fd, packet, PACKET_LEN + 1, 0);
    printf("\e[2K\e[1D");
    printf("%s", packet);
  }

  return NULL;
}

int main(int argc, char *argv[]) {
  int sock_fd;
  struct addrinfo hints;

  char message[MSG_LEN + 1];
  char name[NAME_LEN + 1];
  char timestamp[TIME_LEN + 1];

  time_t rawtime;
  struct tm *time_data = {0};

  pthread_t listen_thread;

  if (argc != 2) {
    fprintf(stderr, "usage: client hostname\n");
    exit(1);
  }

  /* set up structs */
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_flags = AI_PASSIVE; 	/* use my IP */

  init_socket(argv[1], &hints, &sock_fd);

  /* send name */
  gethostname(name, NAME_LEN + 1); 
  send(sock_fd, name, strlen(name), 0);

  if (pthread_create(&listen_thread, NULL, listener_thread, &sock_fd)) {
    perror("client: pthread");
    exit(1);
  }

  while(1) {
    fgets(message, MSG_LEN, stdin); 

    /* ignore empty messages */
    while (message[0] == '\n') {
      printf("\e[1A");
      fgets(message, MSG_LEN, stdin); 
    }

    send(sock_fd, message, strlen(message), 0);

    get_time(&rawtime, time_data, timestamp);
    printf("\e[K\e[1A");
    printf("[%s] %s: %s", timestamp, name, message);
  }

  if (pthread_join(listen_thread, NULL)) {
    perror("client: pthread join");
    exit(1);
  }

  close(sock_fd);

  return 0;
}
