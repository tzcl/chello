#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT "8096"
#define BACKLOG 3
#define NAME_LEN 8
#define TIME_LEN 8
#define FORMAT_LEN 5
#define HEADER_LEN (NAME_LEN + TIME_LEN + FORMAT_LEN) 
#define PACKET_LEN 2048
#define MSG_LEN (PACKET_LEN - HEADER_LEN)
#define AEST (+10+1)		/* daylight savings */
#define MAX_CLIENTS 10 		/* 10+ epoll is much more efficient */

/* TODO */
/* server commands? */
/* mute, kick */
/* allow server to message? */
/* error checking */
/* string validation */
/* string length */

/* get sockaddr, IPv4 or IPv6: */
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

void init_socket(int *sock_fd, struct addrinfo *hints) {
  int status, yes = 1;
  struct addrinfo *res, *p;
  
  if ((status = getaddrinfo(NULL, PORT, hints, &res)) != 0) {
    fprintf(stderr, "get addrinfo error: %s\n", gai_strerror(status));
    exit(1);
  }

  /* bind to the first actual result */
  for (p = res; p != NULL; p = p->ai_next) {
    if ((*sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("server: socket");
      continue;
    }

    /* allow multiple connections to socket */
    if (setsockopt(*sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1) {
      perror("setsockopt");
      exit(1);
    }

    if (bind(*sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(*sock_fd);
      perror("server: bind");
      exit(1);
    }

    break;
  }

  freeaddrinfo(res);

  if (!p) {
    fprintf(stderr, "server: failed to bind\n");
    exit(1);
  }

  if (listen(*sock_fd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }
}

void accept_client(int *new_fd, int listener_fd, char name[], char message[]) {
  struct sockaddr_storage client_addr;
  socklen_t sin_size;
  char client_ip[INET6_ADDRSTRLEN];

  sin_size = sizeof client_addr;
  *new_fd = accept(listener_fd, (struct sockaddr *)&client_addr, &sin_size);
  if (*new_fd == -1) {
    perror("server: accept");
    exit(1);
  }

  inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *)&client_addr), client_ip, sizeof client_ip);

  memset(message, 0, MSG_LEN + 1);

  if (recv(*new_fd, name, NAME_LEN + 1, 0) <= 0) {
    snprintf(message, MSG_LEN + 1, "Server: connection from %s\n", client_ip);
  }
  snprintf(message, MSG_LEN + 1, "Server: connection from %s (%s)\n", name, client_ip);
}

void broadcast_message(char timestamp[], char name[], char message[], int clients[], int exclude) {
  char packet[PACKET_LEN + 1] = {0};
  if (timestamp) {
    strcat(packet, "[");
    strcat(packet, timestamp);
    strcat(packet, "] ");
  }
  if (name) {
    strcat(packet, name); 
    strcat(packet, ": ");
  }
  strcat(packet, message);

  for (int i = 0; i < MAX_CLIENTS; i++) {
    if (clients[i] > 0 && i != exclude) {
      if (send(clients[i], packet, strlen(packet), 0) == -1) {
	perror("server: broadcast");
	exit(1);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  struct addrinfo hints;
  int listener_fd, sock_fd;
  int bytes_read;

  /* set of file descriptors */
  fd_set fds;
  int max_fd, activity;
  int clients[MAX_CLIENTS] = {0};
  char names[MAX_CLIENTS][NAME_LEN + 1];
  char name[NAME_LEN + 1];

  char message[MSG_LEN + 1] = {0};
  char timestamp[TIME_LEN + 1] = {0};

  time_t rawtime;
  struct tm *time_data = {0};

  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; 	/* use my IP */

  init_socket(&listener_fd, &hints);

  printf("server: waiting for connections...\n");

  /* sigaction(SIGPIPE, &(struct sigaction){SIG_IGN}, NULL); */


  while(1) {
    /* clear the socket set */
    FD_ZERO(&fds);

    /* reset strings */
    memset(name, 0, NAME_LEN + 1);
    memset(message, 0, MSG_LEN + 1);

    /* add listener socket to set */
    FD_SET(listener_fd, &fds);
    max_fd = listener_fd;

    /* add child sockets to set */
    for (int i = 0; i < MAX_CLIENTS; i++) {
      sock_fd = clients[i];
      if(sock_fd > 0) FD_SET(sock_fd, &fds);
      if(sock_fd > max_fd) max_fd = sock_fd;
    }

    /* wait for activity on one of the sockets */
    /* timeout is NULL so wait indefinitely */
    activity = select(max_fd + 1, &fds, NULL, NULL, NULL);

    if ((activity < 0) && (errno != EINTR)) {
      perror("server: select");
      exit(1);
    }

    /* activity on listener socket: new connection */
    if (FD_ISSET(listener_fd, &fds)) {
      accept_client(&sock_fd, listener_fd, name, message);

      /* add socket + name to set */
      for (int i = 0; i < MAX_CLIENTS; i++) {
	if (clients[i] == 0) {
	  clients[i] = sock_fd;
	  strcpy(names[i], name);
	  break;
	}
      }

      printf("%s", message);

      broadcast_message(NULL, NULL, message, clients, -1);
    }

    /* activity on other socket: disconnection or new message */
    for (int i = 0; i < MAX_CLIENTS; i++) {
      sock_fd = clients[i];

      if (FD_ISSET(sock_fd, &fds)) {
	if ((bytes_read = read(sock_fd, message, MSG_LEN + 1)) == 0) {
	  snprintf(message, MSG_LEN + 1, "Server: %s has disconnected\n", names[i]);
	  printf("%s", message);

	  close(sock_fd);
	  clients[i] = 0;

	  broadcast_message(NULL, NULL, message, clients, -1);
	} else {
	  message[bytes_read] = '\0';

	  get_time(&rawtime, time_data, timestamp);
	  printf("[%s] %s: %s", timestamp, names[i], message);

	  broadcast_message(timestamp, names[i], message, clients, i);
	}
      }
    }
  }

  close(listener_fd);

  return 0;
}
