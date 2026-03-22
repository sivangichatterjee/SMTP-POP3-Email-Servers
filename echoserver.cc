#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <string.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <strings.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <getopt.h>
#define MAX_CLIENTS 100

#define BUF_SIZE 4096

bool verbose = false;          // -v option: print debug logs to stderr
int listen_fd;                 // Listening socket for accept()
volatile int keep_running = 1; // Set to 0 by SIGINT handler to stop accept loop
void *worker(void *arg);
void handle_sigint(int sig);

static int clients[MAX_CLIENTS];
static int client_count = 0;
static pthread_mutex_t clients_mu = PTHREAD_MUTEX_INITIALIZER;

// To track active client sockets for handling Ctrl C server shutdown
static void add_client(int fd)
{
  pthread_mutex_lock(&clients_mu);
  if (client_count < MAX_CLIENTS)
  {
    // If >= MAX_CLIENTS, we silently drop tracking; but we still accept the fd.
    clients[client_count++] = fd;
  }
  pthread_mutex_unlock(&clients_mu);
}

// To remove clients
static void remove_client(int fd)
{
  pthread_mutex_lock(&clients_mu);
  for (int i = 0; i < client_count; i++)
  {
    if (clients[i] == fd)
    {
      clients[i] = clients[client_count - 1];
      client_count--;
      break;
    }
  }
  pthread_mutex_unlock(&clients_mu);
}

int main(int argc, char *argv[])
{

  // SIGINT handler so Ctrl+C triggers graceful shutdown
  signal(SIGINT, handle_sigint);
  int port = 10000; // default port if no parameter given
  int opt;

  // Create listening socket
  listen_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0)
  {
    perror("socket error");
    exit(1);
  }
  // Prepare server address
  struct sockaddr_in servaddr;
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET;
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
  while ((opt = getopt(argc, argv, "p:av")) != -1)
  {
    switch (opt)
    {
    case 'p': // if -p provided take that port number
      port = atoi(optarg);
      break;
    case 'v': // for debugging purposes
      verbose = true;
      break;
    case 'a': // requirement as per assignment
      fprintf(stderr, "Sivangi Chatterjee(chatter2)\n");
      return 0;
    }
  }
  servaddr.sin_port = htons(port);

  // bind(): associate socket with IP/port.
  if (bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)) < 0)
  {
    perror("bind");
    close(listen_fd);
    exit(1);
  }

  // listen(): start accepting connections.
  if (listen(listen_fd, 100) < 0)
  {
    perror("listen");
    close(listen_fd);
    exit(1);
  }
  while (keep_running)
  {
    struct sockaddr_in clientaddr;
    socklen_t clientaddrlen = sizeof(clientaddr);

    // Allocate per-thread copy of fd
    int *client_fd = (int *)malloc(sizeof(int));
    *client_fd = accept(listen_fd, (struct sockaddr *)&clientaddr, &clientaddrlen);
    if (*client_fd < 0)
    {
      int err = errno;
      free(client_fd);
      // If we are shutting down (Ctrl+C) stop looping.
      if (!keep_running)
        break;
      // If accept() was interrupted by a signal, just retry.
      if (err == EINTR)
        continue;

      // Otherwise print why accept failed and keep running.
      perror("accept");
      continue;
    }
    else
    {
      if (verbose)
      {
        fprintf(stderr, "[%d] New connection\n", *client_fd);
      }
    }

    pthread_t thread;
    pthread_create(&thread, NULL, worker, client_fd);
    pthread_detach(thread);
  }
  // notify all currently tracked clients, then close them
  const char *msg = "-ERR Server shutting down\r\n";
  pthread_mutex_lock(&clients_mu);
  for (int i = 0; i < client_count; i++)
  {
    int fd = clients[i];
    (void)write(fd, msg, strlen(msg));
    close(fd);
  }
  client_count = 0;
  pthread_mutex_unlock(&clients_mu);

  _exit(0);
  return 0;
}

void *worker(void *arg)
{
  int comm_fd = *(int *)arg;
  free(arg);
  // Track active client so shutdown can message it.
  add_client(comm_fd);

  // send greeting
  const char *greet = "+OK Server ready (Author: Sivangi Chatterjee / chatter2)\r\n";
  if (verbose)
    fprintf(stderr, "[%d] S: %s", comm_fd, greet);
  if (write(comm_fd, greet, strlen(greet)) < 0)
  {
    remove_client(comm_fd);
    close(comm_fd);
    return NULL;
  }

  char buf[BUF_SIZE];
  int len = 0;

  while (true)
  {
    // n<=0: client closed connection (0) or error (<0)
    int n = read(comm_fd, buf + len, BUF_SIZE - len - 1);
    if (n <= 0)
    {

      if (verbose)
        fprintf(stderr, "[%d] Connection closed\n", comm_fd);
      break;
    }

    len += n;
    buf[len] = '\0';

    char *line_end;
    const char *output;
    while ((line_end = strstr(buf, "\r\n")) != NULL)
    {
      *line_end = '\0';
      char *cmd = buf;

      if (verbose)
      {
        fprintf(stderr, "[%d] C: %s\n", comm_fd, cmd);
      }
      // case insensitive command parsing
      if (strncasecmp(cmd, "ECHO ", 5) == 0)
      {
        char response[1100]; // Echo back everything after "ECHO "
        snprintf(response, sizeof(response), "+OK %s\r\n", cmd + 5);
        if (verbose)
        {
          fprintf(stderr, "[%d] S: %s", comm_fd, response);
        }
        write(comm_fd, response, strlen(response));
      }
      else if (strcasecmp(cmd, "QUIT") == 0)
      {
        // QUIT: respond with goodbye and close connection.
        output = "+OK Goodbye!\r\n";
        write(comm_fd, output, strlen(output));
        if (verbose)
          fprintf(stderr, "[%d] S: %s", comm_fd, output);
        close(comm_fd);
        // For -v, log closure after QUIT
        if (verbose)
          fprintf(stderr, "[%d] Connection closed\n", comm_fd);
        remove_client(comm_fd);
        return NULL;
      }
      else
      {
        // unknown command handled
        output = "-ERR Unknown command\r\n";
        write(comm_fd, output, strlen(output));
        if (verbose)
          fprintf(stderr, "[%d] S: %s", comm_fd, output);
      }

      char *next_data = line_end + 2;
      int remaining_len = len - (next_data - buf);

      // Move remaining bytes (after CRLF) to the front
      memmove(buf, next_data, remaining_len);
      len = remaining_len;
      buf[len] = '\0';
    }
    if (BUF_SIZE - len - 1 == 0)
    {
      const char *toolong = "-ERR Line too long\r\n";
      if (verbose)
        fprintf(stderr, "[%d] S: %s", comm_fd, toolong);
      (void)write(comm_fd, toolong, strlen(toolong));

      // Reset buffer so we can keep going
      len = 0;
      buf[0] = '\0';
    }
  }
  // Cleanup when client disconnects normally
  remove_client(comm_fd);
  close(comm_fd);
  return NULL;
}
void handle_sigint(int sig)
{
  // Set flag to stop accept loop and close listen_fd
  (void)sig;
  keep_running = 0;
  close(listen_fd);
}