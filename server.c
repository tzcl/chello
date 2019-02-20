#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <string.h>
#include <errno.h>
#include <signal.h>
#include <time.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#define PORT "8096"
#define BACKLOG 10
#define MSG_LEN 256
#define NAME_LEN 8 
#define TIME_LEN 9
#define AEST (+10+1)

/* TODO */
/* server commands? */
/* mute, kick */
/* allow server to message? */

void sigchld_handler(int s) {
  /* waitpid() might overwrite errno, so we save and restore it: */
  int saved_errno = errno;

  while(waitpid(-1, NULL, WNOHANG) > 0);

  errno = saved_errno;
}

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
  snprintf(timestamp, TIME_LEN, "%02d:%02d:%02d", (time_data->tm_hour + AEST) % 24, time_data->tm_min, time_data->tm_sec);
}

int main(int argc, char *argv[]) {

  /* check arguments */

  int status;
  struct addrinfo hints, *res, *p;
  int sock_fd, new_fd;

  struct sockaddr_storage client_addr;
  socklen_t sin_size;
  char client_ip[INET6_ADDRSTRLEN];

  struct sigaction sa;

  int yes = 1;

  char message[MSG_LEN] = {0};
  char name[NAME_LEN] = {0};
  char timestamp[TIME_LEN] = {0};

  time_t rawtime;
  struct tm *time_data = {0};

  /* set up structs */
  memset(&hints, 0, sizeof hints);
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_PASSIVE; 	/* use my IP */

  if ((status = getaddrinfo(NULL, PORT, &hints, &res)) != 0) {
    fprintf(stderr, "get addrinfo error: %s\n", gai_strerror(status));
    exit(1);
  }

  /* bind to the first actual result */
  for (p = res; p != NULL; p = p->ai_next) {
    if ((sock_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
      perror("server: socket");
      continue;
    }

    /* allows us to reuse port */
    if (setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes) == -1) {
      perror("setsockopt");
      exit(1);
    }

    if (bind(sock_fd, p->ai_addr, p->ai_addrlen) == -1) {
      close(sock_fd);
      perror("server: bind");
      exit(1);
    }

    break;
  }

  /* finished setting up socket */
  freeaddrinfo(res);

  if (!p) {
    fprintf(stderr, "server: failed to bind\n");
    exit(1);
  }

  if (listen(sock_fd, BACKLOG) == -1) {
    perror("listen");
    exit(1);
  }

  /* reap dead processes */
  sa.sa_handler = sigchld_handler;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = SA_RESTART;
  if (sigaction(SIGCHLD, &sa, NULL) == -1) {
    perror("sigaction");
    exit(1);
  }

  printf("server: waiting for connections...\n");

  /* main accept() loop */
  while(1) {
    sin_size = sizeof client_addr;
    new_fd = accept(sock_fd, (struct sockaddr *)&client_addr, &sin_size);
    if (new_fd == -1) {
      perror("accept");
      continue;
    }

    inet_ntop(client_addr.ss_family, get_in_addr((struct sockaddr *)&client_addr), client_ip, sizeof client_ip);

    get_time(&rawtime, time_data, timestamp);
    
    /* receive name */
    if (recv(new_fd, name, NAME_LEN, 0) == -1) {
      printf("server: connection from %s\n", client_ip); 
    }
    printf("server: connection from %s (%s)\n", name, client_ip);

    if (!fork()) {
      /* child process */
      close(sock_fd);

      while (recv(new_fd, message, MSG_LEN, 0) > 0) {
	get_time(&rawtime, time_data, timestamp);

	printf("[%s] %s: %s", timestamp, name, message);

	send(new_fd, timestamp, strlen(timestamp), 0);

	/* terminate child proces? */
	memset(message, 0, MSG_LEN);
	memset(timestamp, 0, TIME_LEN);
      }

      printf("server: %s has disconnected\n", name);

      close(new_fd);
      exit(0);
    }

    /* parent process */
    close(new_fd);
    memset(name, 0, NAME_LEN);
  }

  return 0;
}
