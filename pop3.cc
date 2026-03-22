#include <stdlib.h>
#include <stdio.h>
#include <openssl/md5.h>
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
#include <sys/file.h>
#include <limits.h>
#define MAX_CLIENTS 100

#define BUF_SIZE 4096

#define MAX_RCPTS 100
#define RCPT_LEN 256

#define MAX_MBOX_LOCKS 512
#define MBOX_PATH_LEN 1024

bool verbose = false;                   // -v option: print debug logs to stderr
int listen_fd;                          // Listening socket for accept()
volatile sig_atomic_t keep_running = 1; // Set to 0 by SIGINT handler to stop accept loop
void *worker(void *arg);
void handle_sigint(int sig);
char rcpt_list[MAX_RCPTS][RCPT_LEN];
char rcpt_user[RCPT_LEN];
static pthread_mutex_t *get_mbox_mutex(const char *path);
static int append_bytes(char **buf, size_t *len, size_t *cap, const char *src, size_t n);
static int compute_uidl_for_msg(FILE *mail_fp, int msg_no, char uid_hex_out[33]);
static int apply_deletions_to_mbox(FILE *mail_fp, const char *mailbox_path,
                                   const int *msg_deleted, size_t msg_count_total);
typedef struct
{
  bool used;
  char path[MBOX_PATH_LEN];
  pthread_mutex_t mu;
} mbox_lock_entry_t;

static mbox_lock_entry_t mbox_lock_table[MAX_MBOX_LOCKS];
static pthread_mutex_t mbox_lock_table_mu = PTHREAD_MUTEX_INITIALIZER;
static int clients[MAX_CLIENTS];
static int client_count = 0;
static pthread_mutex_t clients_mu = PTHREAD_MUTEX_INITIALIZER;

const char *maildir = NULL;

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

void computeDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer)
{
  /* The digest will be written to digestBuffer, which must be at least MD5_DIGEST_LENGTH bytes long */

  MD5_CTX c;
  MD5_Init(&c);
  MD5_Update(&c, data, dataLengthBytes);
  MD5_Final(digestBuffer, &c);
}

void digestToHex(const unsigned char *digestBuffer, char *hexOut)
{
  // hexOut must be at least 33 bytes
  for (int i = 0; i < 16; i++)
  {
    sprintf(hexOut + (2 * i), "%02x", digestBuffer[i]);
  }
  hexOut[32] = '\0';
}

int main(int argc, char *argv[])
{

  // SIGINT handler so Ctrl+C triggers graceful shutdown
  signal(SIGINT, handle_sigint);
  signal(SIGPIPE, SIG_IGN);
  int port = 11000; // default port if no parameter given
  int opt;

  // Create listening socket
  listen_fd = socket(PF_INET, SOCK_STREAM, 0);
  if (listen_fd < 0)
  {
    perror("socket error");
    exit(1);
  }

  // For address reusability
  int optval = 1;
  if (setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
  {
    perror("setsockopt SO_REUSEADDR");
    close(listen_fd);
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
  if (optind >= argc)
  {
    fprintf(stderr, "Missing maildir\n");
    exit(1);
  }
  maildir = argv[optind]; // mail directory to be provided in the command
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
    if (client_fd == NULL)
    {
      perror("malloc");
      continue;
    }
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
    int rc = pthread_create(&thread, NULL, worker, client_fd);
    if (rc != 0)
    {
      perror("pthread_create");
      close(*client_fd);
      free(client_fd);
      continue;
    }
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
  bool user_validated = false;
  bool authorization = false, transaction = false, update = false;
  const char *PWD = "cis505";
  int comm_fd = *(int *)arg;
  // int msg_count = 0;
  char *line = NULL;
  size_t cap = 0; // capacity managed by getline
  ssize_t nread;
  size_t total_octets = 0;
  int in_message = 0;
  size_t current_octets = 0;
  int active = 0, count = 0, active_msg_count = 0;
  size_t msg_meta_cap = 0;

  size_t msg_count_total = 0; // total parsed at PASS
  size_t *msg_octets = NULL;  // length = msg_count_total
  int *msg_deleted = NULL;
  char current_user[256] = {0};
  char current_path[1024] = {0};
  FILE *fp = NULL;
  int fd = -1;
  pthread_mutex_t *mu = NULL;
  bool maildrop_locked = false;

  free(arg);
  // Track active client so shutdown can message it.
  add_client(comm_fd);

  // send greeting
  const char *greet = "+OK POP3 ready [localhost]\r\n";
  authorization = true;
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
    const char *resp;
    const char *output;

    char rcpt_user[256];
    while ((line_end = strstr(buf, "\r\n")) != NULL)
    {
      *line_end = '\0';
      char *cmd = buf;
      char path[1024];

      if (verbose)
      {
        fprintf(stderr, "[%d] C: %s\n", comm_fd, cmd);
      }
      // case insensitive command parsing

      // AUTHORIZATION
      // 1. USER command - user authorization

      if (strncasecmp(cmd, "USER", 4) == 0)
      {
        if (!authorization)
        {
          resp = "-ERR wrong order of commands. Not in authorization state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else if (cmd[4] != ' ' || cmd[5] == '\0')
        {
          resp = "-ERR User not mentioned\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        const char *p = cmd + 5;
        char rcpt_user[256];
        while (*p == ' ')
          p++;
        const char *last = strchr(p, '\0');
        size_t user_len = (size_t)(last - p);
        if (user_len >= sizeof(rcpt_user))
        {
          resp = "-ERR username too long\r\n";
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        memcpy(rcpt_user, p, user_len);
        rcpt_user[user_len] = '\0';

        snprintf(path, sizeof(path), "%s/%s.mbox", maildir, rcpt_user);

        // check if mailbox exists
        if (access(path, F_OK) != 0)
        {
          resp = "-ERR no such user\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          user_validated = false;
          current_user[0] = '\0';
          current_path[0] = '\0';
          goto consume;
        }
        else
        {
          resp = "+OK user accepted\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          user_validated = true;

          // to use later during PASS for user authentication
          strncpy(current_user, rcpt_user, sizeof(current_user) - 1);
          current_user[sizeof(current_user) - 1] = '\0';
          snprintf(current_path, sizeof(current_path), "%s/%s.mbox", maildir, current_user);

          goto consume;
        }
      }

      // 2. PASS - password authentication
      else if (strncasecmp(cmd, "PASS", 4) == 0)
      {
        // needs to be in authorization state
        if (!authorization)
        {
          resp = "-ERR wrong order of commands. Not in authorization state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        // user needs to be validated before pass
        else if (authorization && !user_validated)
        {
          resp = "-ERR wrong order of commands. User not validated\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else if (cmd[4] != ' ' || cmd[5] == '\0')
        {
          resp = "-ERR Password not mentioned\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else
        {
          const char *p = cmd + 5;
          char pwd[256];
          while (*p == ' ')
            p++;
          const char *last = strchr(p, '\0');
          size_t pwd_len = (size_t)(last - p);
          memcpy(pwd, p, pwd_len);
          pwd[pwd_len] = '\0';

          if (strcasecmp(pwd, PWD) != 0)
          {
            resp = "-ERR Authentication failed\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else
          {
            // obtain lock on the fd
            mu = get_mbox_mutex(current_path);
            if (mu == NULL)
            {
              resp = "-ERR cannot allocate mailbox lock\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }
            pthread_mutex_lock(mu);

            fp = fopen(current_path, "r"); // open file
            if (!fp)
            {
              pthread_mutex_unlock(mu);
              resp = "-ERR Cannot open file\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            // to prohibit different programs from accessing the same mailbox at the same time
            fd = fileno(fp);
            if (flock(fd, LOCK_EX) != 0)
            {
              fclose(fp);
              pthread_mutex_unlock(mu);
              resp = "-ERR Cannot obtain lock\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }
            maildrop_locked = true; // set this to true
            // reset parse/session metadata
            msg_count_total = 0;
            total_octets = 0;
            count = 0;
            in_message = 0;
            current_octets = 0;

            free(msg_octets);
            free(msg_deleted);
            msg_octets = NULL;
            msg_deleted = NULL;
            msg_meta_cap = 0;

            free(line);
            line = NULL;
            cap = 0;

            rewind(fp); // from the beginning

            while ((nread = getline(&line, &cap, fp)) != -1)
            {
              if (strncmp(line, "From ", 5) == 0)
              {
                // finalize previous message
                if (in_message)
                {
                  if ((size_t)count == msg_meta_cap)
                  {
                    size_t new_cap = (msg_meta_cap == 0) ? 8 : msg_meta_cap * 2;
                    size_t *new_octets = (size_t *)realloc(msg_octets, new_cap * sizeof(size_t));
                    int *new_deleted = (int *)realloc(msg_deleted, new_cap * sizeof(int));
                    if (new_octets == NULL || new_deleted == NULL)
                    {
                      free(new_octets);
                      free(new_deleted);
                      free(msg_octets);
                      free(msg_deleted);
                      msg_octets = NULL;
                      msg_deleted = NULL;
                      msg_meta_cap = 0;

                      free(line);
                      line = NULL;
                      cap = 0;

                      // release locks in case of failure
                      flock(fd, LOCK_UN);
                      fclose(fp);
                      pthread_mutex_unlock(mu);

                      maildrop_locked = false;
                      fp = NULL;
                      fd = -1;
                      mu = NULL;

                      resp = "-ERR out of memory\r\n";
                      if (verbose)
                        fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                      write(comm_fd, resp, strlen(resp));
                      goto consume;
                    }
                    msg_octets = new_octets;
                    msg_deleted = new_deleted;
                    msg_meta_cap = new_cap;
                  }

                  msg_octets[count] = current_octets;
                  msg_deleted[count] = 0;

                  total_octets += current_octets;
                  count++;
                  current_octets = 0;
                }

                in_message = 1;
                continue; // do not count mbox separator
              }

              if (!in_message)
                continue; // ignore junk before first From line

              size_t len = (size_t)nread;
              while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
                len--;

              current_octets += len + 2; // POP3 CRLF
            }

            if (in_message)
            {
              if ((size_t)count == msg_meta_cap)
              {
                size_t new_cap = (msg_meta_cap == 0) ? 8 : msg_meta_cap * 2;
                size_t *new_octets = (size_t *)realloc(msg_octets, new_cap * sizeof(size_t));
                int *new_deleted = (int *)realloc(msg_deleted, new_cap * sizeof(int));
                if (new_octets == NULL || new_deleted == NULL)
                {
                  free(new_octets);
                  free(new_deleted);
                  free(msg_octets);
                  free(msg_deleted);
                  msg_octets = NULL;
                  msg_deleted = NULL;
                  msg_meta_cap = 0;

                  free(line);
                  line = NULL;
                  cap = 0;

                  flock(fd, LOCK_UN);
                  fclose(fp);
                  pthread_mutex_unlock(mu);

                  maildrop_locked = false;
                  fp = NULL;
                  fd = -1;
                  mu = NULL;

                  resp = "-ERR out of memory\r\n";
                  if (verbose)
                    fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                  write(comm_fd, resp, strlen(resp));
                  goto consume;
                }
                msg_octets = new_octets;
                msg_deleted = new_deleted;
                msg_meta_cap = new_cap;
              }

              msg_octets[count] = current_octets;
              msg_deleted[count] = 0;

              total_octets += current_octets;
              count++;
            }

            msg_count_total = (size_t)count;

            free(line);
            line = NULL;
            cap = 0;

            resp = "+OK Maildrop locked and ready\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s(%s maildrop has %d messages)\n", comm_fd, resp, current_user, count);
            write(comm_fd, resp, strlen(resp));

            authorization = false; // authorization done
            transaction = true;    // starting transaction
            goto consume;
          }
        }
      }

      // 3. STAT
      else if (strncasecmp(cmd, "STAT", 4) == 0)
      {
        if (!transaction)
        {
          resp = "-ERR wrong order of commands. Not in transaction state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else
        {
          size_t live_count = 0;
          size_t live_octets = 0;

          for (size_t i = 0; i < msg_count_total; i++)
          {
            if (msg_deleted[i] == 0)
            {
              live_count++;
              live_octets += msg_octets[i];
            }
          }

          char stat_resp[128];
          snprintf(stat_resp, sizeof(stat_resp), "+OK %zu %zu\r\n", live_count, live_octets);

          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, stat_resp);
          write(comm_fd, stat_resp, strlen(stat_resp));
          goto consume;
        }
      }

      // RETR
      else if (strncasecmp(cmd, "RETR", 4) == 0)
      {
        // needs to be in transaction state
        if (!transaction)
        {
          resp = "-ERR wrong order of commands. Not in transaction state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else
        {
          if (cmd[4] != ' ' || cmd[5] == '\0')
          {
            resp = "-ERR Message number not mentioned\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          const char *p = cmd + 5;
          while (*p == ' ')
            p++;
          char *endptr;
          long msg_no_long = strtol(p, &endptr, 10); // convert from char

          // no digits found
          if (endptr == p)
          {
            resp = "-ERR invalid message number\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }

          // allow trailing spaces only
          while (*endptr == ' ')
            endptr++;
          if (*endptr != '\0')
          {
            resp = "-ERR invalid syntax\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }

          // must be positive and within int range (optional but good)
          if (msg_no_long <= 0 || msg_no_long > INT_MAX)
          {
            resp = "-ERR invalid message number\r\n";
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }

          int msg_no = (int)msg_no_long;
          int idx = msg_no - 1;

          // RANGE CHECK (required)
          if (msg_no < 1 || (size_t)msg_no > msg_count_total)
          {
            resp = "-ERR no such message\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }

          if (msg_deleted[idx] == 1)
          {
            resp = "-ERR No such message found\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else
          {
            if (!maildrop_locked || fp == NULL)
            {
              resp = "-ERR maildrop not available\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            char retr_resp[128];
            snprintf(retr_resp, sizeof(retr_resp), "+OK %zu octets\r\n", msg_octets[idx]);

            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, retr_resp);
            write(comm_fd, retr_resp, strlen(retr_resp));

            // Parse the already-locked mailbox file from the beginning
            rewind(fp);

            char *rline = NULL;
            size_t rcap = 0;
            ssize_t rnread;
            int curr_msg_no = 0;
            int in_target = 0;

            while ((rnread = getline(&rline, &rcap, fp)) != -1)
            {
              if (strncmp(rline, "From ", 5) == 0)
              {
                curr_msg_no++;

                // If we were already inside target, this separator starts next message -> target ends
                if (in_target)
                  break;

                // Target message starts after this separator line
                if (curr_msg_no == msg_no)
                  in_target = 1;

                continue; // never send mbox separator
              }

              if (!in_target)
                continue;

              // Send message line as POP3 line (CRLF normalized)
              size_t len = (size_t)rnread;
              while (len > 0 && (rline[len - 1] == '\n' || rline[len - 1] == '\r'))
                len--;

              // POP3 dot-stuffing for multi-line response
              if (len > 0 && rline[0] == '.')
                write(comm_fd, ".", 1);

              if (len > 0)
              {
                if (verbose)
                  fprintf(stderr, "[%d] S: %s", comm_fd, rline);
                write(comm_fd, rline, len);
              }

              // if (verbose)
              //   fprintf(stderr, "[%d] S: \r\n", comm_fd);
              write(comm_fd, "\r\n", 2);
            }

            free(rline);

            // POP3 multi-line terminator
            if (verbose)
              fprintf(stderr, "[%d] S: .\r\n", comm_fd);
            write(comm_fd, ".\r\n", 3);

            goto consume;
          }
        }
      }

      // DELE

      else if (strncasecmp(cmd, "DELE", 4) == 0)
      {
        // needs to be in transaction
        if (!transaction)
        {
          resp = "-ERR wrong order of commands. Not in transaction state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else
        {
          if (cmd[4] != ' ' || cmd[5] == '\0')
          {
            resp = "-ERR Message number not mentioned\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          const char *p = cmd + 5;
          while (*p == ' ')
            p++;
          char *endptr;
          long msg_no_long = strtol(p, &endptr, 10); // convert from char

          // no digits found
          if (endptr == p)
          {
            resp = "-ERR invalid message number\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }

          // allow trailing spaces only
          while (*endptr == ' ')
            endptr++;
          if (*endptr != '\0')
          {
            resp = "-ERR invalid syntax\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }

          // must be positive and within int range (optional but good)
          if (msg_no_long <= 0 || msg_no_long > INT_MAX)
          {
            resp = "-ERR invalid message number\r\n";
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }

          int msg_no = (int)msg_no_long;
          int idx = msg_no - 1;

          // RANGE CHECK (required)
          if (msg_no < 1 || (size_t)msg_no > msg_count_total)
          {
            resp = "-ERR No such message found\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          // if already deleted
          if (msg_deleted[idx] == 1)
          {
            resp = "-ERR No such message found\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else
          {

            msg_deleted[idx] = 1; // mark as deleted
            char retr_resp[128];
            snprintf(retr_resp, sizeof(retr_resp), "+OK message %d deleted\r\n", msg_no);
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, retr_resp);
            write(comm_fd, retr_resp, strlen(retr_resp));
            goto consume;
          }
        }
      }

      // RSET block
      else if (strcasecmp(cmd, "RSET") == 0)
      {
        if (!transaction)
        {
          resp = "-ERR wrong order of commands. Not in transaction state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else
        {
          for (size_t i = 0; i < msg_count_total; i++)
          {
            msg_deleted[i] = 0;
          }

          char rset_resp[128];
          snprintf(rset_resp, sizeof(rset_resp), "+OK %zu messages\r\n", msg_count_total);

          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, rset_resp);
          write(comm_fd, rset_resp, strlen(rset_resp));
          goto consume;
        }
      }

      // LIST block

      else if (strncasecmp(cmd, "LIST", 4) == 0)
      {
        if (!transaction)
        {
          resp = "-ERR wrong order of commands. Not in transaction state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else
        {

          if (cmd[4] == '\0') // if no parameters provided
          {

            size_t live_count = 0;
            size_t live_octets = 0;

            for (size_t i = 0; i < msg_count_total; i++)
            {
              if (msg_deleted[i] == 0)
              {
                live_count++;                 // count undeleted messages
                live_octets += msg_octets[i]; // add up to octets
              }
            }

            char stat_resp[128];
            snprintf(stat_resp, sizeof(stat_resp), "+OK %zu messages (%zu octets)\r\n", live_count, live_octets);

            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, stat_resp);
            write(comm_fd, stat_resp, strlen(stat_resp));
            char resp[128];
            // list out the messages
            for (int i = 0; i < msg_count_total; i++)
            {
              if (msg_deleted[i] == 0)
              {
                snprintf(resp, sizeof(resp), "%d %zu\r\n", (i + 1), msg_octets[i]);
                if (verbose)
                  fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                write(comm_fd, resp, strlen(resp));
              }
            }
            if (verbose)
              fprintf(stderr, "[%d] S:.\r\n", comm_fd);
            write(comm_fd, ".\r\n", 3);
            goto consume;
          }
          else if (cmd[4] != ' ')
          {
            resp = "-ERR Syntax error in command\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else // if parameters provided
          {
            const char *p = cmd + 5;
            while (*p == ' ')
              p++;
            char *endptr;
            long msg_no_long = strtol(p, &endptr, 10); // convert from char

            // no digits found
            if (endptr == p)
            {
              resp = "-ERR invalid message number\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            // allow trailing spaces only
            while (*endptr == ' ')
              endptr++;
            if (*endptr != '\0')
            {
              resp = "-ERR invalid syntax\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            // must be positive and within int range (optional but good)
            if (msg_no_long <= 0 || msg_no_long > INT_MAX)
            {
              resp = "-ERR invalid message number\r\n";
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            int msg_no = (int)msg_no_long;
            int idx = msg_no - 1; // since msg_deleted is 0 indexed

            // RANGE CHECK (required)
            if (msg_no < 1 || (size_t)msg_no > msg_count_total)
            {
              resp = "-ERR no such message\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            if (msg_deleted[idx] == 1)
            {
              resp = "-ERR No such message found\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }
            else
            {
              char stat_resp[128];
              snprintf(stat_resp, sizeof(stat_resp), "+OK %d %zu\r\n", msg_no, msg_octets[idx]);

              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, stat_resp);
              write(comm_fd, stat_resp, strlen(stat_resp));
              goto consume;
            }
          }
        }
      }
      // UIDL command
      else if (strncasecmp(cmd, "UIDL", 4) == 0)
      {
        // needs to be in trnasaction
        if (!transaction)
        {
          resp = "-ERR wrong order of commands. Not in transaction state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else
        {
          if (fp == NULL)
          {
            resp = "-ERR maildrop not available\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }

          else if (cmd[4] == '\0') // if no parameters provided
          {
            const char *hdr = "+OK unique-id listing follows\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, hdr);
            write(comm_fd, hdr, strlen(hdr));

            char uid_hex[33];
            char linebuf[256];

            for (size_t i = 0; i < msg_count_total; i++)
            {
              if (msg_deleted[i] != 0)
                continue;
              // compute hashing
              int rc = compute_uidl_for_msg(fp, (int)(i + 1), uid_hex);
              if (rc == -2)
              {
                resp = "-ERR out of memory\r\n";
                if (verbose)
                  fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                write(comm_fd, resp, strlen(resp));
                goto consume;
              }
              else if (rc == -3)
              {
                resp = "-ERR message too large\r\n";
                if (verbose)
                  fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                write(comm_fd, resp, strlen(resp));
                goto consume;
              }
              else if (rc != 0)
              {
                resp = "-ERR could not compute UIDL\r\n";
                if (verbose)
                  fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                write(comm_fd, resp, strlen(resp));
                goto consume;
              }

              // store hashing in linebuf
              snprintf(linebuf, sizeof(linebuf), "%zu %s\r\n", i + 1, uid_hex);
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, linebuf);
              write(comm_fd, linebuf, strlen(linebuf));
            }
            if (verbose)
              fprintf(stderr, "[%d] S:.\r\n", comm_fd);
            write(comm_fd, ".\r\n", 3);
            goto consume;
          }
          else if (cmd[4] != ' ')
          {
            resp = "-ERR Syntax error in command\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else // if parameters provided
          {
            const char *p = cmd + 5;
            while (*p == ' ')
              p++;
            char *endptr;
            long msg_no_long = strtol(p, &endptr, 10); // convert from char

            // no digits found
            if (endptr == p)
            {
              resp = "-ERR invalid message number\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            // allow trailing spaces only
            while (*endptr == ' ')
              endptr++;
            if (*endptr != '\0')
            {
              resp = "-ERR invalid syntax\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            // must be positive and within int range (optional but good)
            if (msg_no_long <= 0 || msg_no_long > INT_MAX)
            {
              resp = "-ERR invalid message number\r\n";
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            int msg_no = (int)msg_no_long;
            int idx = msg_no - 1; // since msg_deleted is 0 indexed

            // RANGE CHECK (required)
            if (msg_no < 1 || (size_t)msg_no > msg_count_total)
            {
              resp = "-ERR no such message\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            if (msg_deleted[idx] == 1)
            {
              resp = "-ERR No such message found\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }
            else
            {
              char uid_hex[33];
              int rc = compute_uidl_for_msg(fp, msg_no, uid_hex);

              if (rc == -2)
                resp = "-ERR out of memory\r\n";
              else if (rc == -3)
                resp = "-ERR message too large\r\n";
              else if (rc != 0)
                resp = "-ERR could not compute UIDL\r\n";
              else
                resp = NULL;

              if (resp != NULL)
              {
                if (verbose)
                  fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                write(comm_fd, resp, strlen(resp));
                goto consume;
              }

              char uidl_resp[256];
              snprintf(uidl_resp, sizeof(uidl_resp), "+OK %d %s\r\n", msg_no, uid_hex);

              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, uidl_resp);
              write(comm_fd, uidl_resp, strlen(uidl_resp));
              goto consume;
            }
          }
        }
      }

      // QUIT (both authorization and transaction)
      else if (strcasecmp(cmd, "QUIT") == 0)
      {
        const char *quit_resp = "+OK POP3 server signing off\r\n";
        // if in authorization
        if (authorization)
        {
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, quit_resp);
          write(comm_fd, quit_resp, strlen(quit_resp));

          // release locks
          if (maildrop_locked && fp != NULL && mu != NULL)
          {
            flock(fd, LOCK_UN);
            fclose(fp);
            pthread_mutex_unlock(mu);
            maildrop_locked = false;
            fp = NULL;
            fd = -1;
            mu = NULL;
          }

          close(comm_fd);
          if (verbose)
            fprintf(stderr, "[%d] Connection closed\n", comm_fd);
          remove_client(comm_fd);
          return NULL;
        }
        // if in transaction delete messages
        else if (transaction)
        {
          transaction = false;
          update = true;

          int rc = 0;
          if (maildrop_locked && fp != NULL && msg_count_total > 0)
          {
            rc = apply_deletions_to_mbox(fp, current_path, msg_deleted, msg_count_total);
          }

          if (rc != 0)
          {
            resp = "-ERR unable to update maildrop\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));

            // release lock and close anyway
            if (maildrop_locked && fp != NULL && mu != NULL)
            {
              flock(fd, LOCK_UN);
              fclose(fp);
              pthread_mutex_unlock(mu);
              maildrop_locked = false;
              fp = NULL;
              fd = -1;
              mu = NULL;
            }

            close(comm_fd);
            if (verbose)
              fprintf(stderr, "[%d] Connection closed\n", comm_fd);
            remove_client(comm_fd);
            return NULL;
          }
          // release locks
          if (maildrop_locked && fp != NULL && mu != NULL)
          {
            flock(fd, LOCK_UN);
            fclose(fp);
            pthread_mutex_unlock(mu);
            maildrop_locked = false;
            fp = NULL;
            fd = -1;
            mu = NULL;
          }

          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, quit_resp);
          write(comm_fd, quit_resp, strlen(quit_resp));

          close(comm_fd);
          if (verbose)
            fprintf(stderr, "[%d] Connection closed\n", comm_fd);
          remove_client(comm_fd);
          return NULL;
        }
        else
        {
          // If neither flag is set (unexpected), still be graceful
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, quit_resp);
          write(comm_fd, quit_resp, strlen(quit_resp));

          close(comm_fd);
          if (verbose)
            fprintf(stderr, "[%d] Connection closed\n", comm_fd);
          remove_client(comm_fd);
          return NULL;
        }
      }
      // NOOP block
      else if (strcasecmp(cmd, "NOOP") == 0)
      {
        if (!transaction)
        {
          resp = "-ERR wrong order of commands. Not in transaction state\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
        else
        {

          resp = "+OK\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }
      }
      else
      {
        // unknown command handled
        output = "-ERR Not supported\r\n";
        write(comm_fd, output, strlen(output));
        if (verbose)
          fprintf(stderr, "[%d] S: %s", comm_fd, output);
        goto consume;
      }
    consume:
    {
      char *next_data = line_end + 2; // line_end points to \r , +2 will point to the next data
      int remaining_len = len - (next_data - buf);
      memmove(buf, next_data, remaining_len); // shifting data to the front of buffer
      len = remaining_len;
      buf[len] = '\0';
      continue;
    }
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
  if (maildrop_locked && fp != NULL && mu != NULL)
  {
    flock(fd, LOCK_UN);
    fclose(fp);
    pthread_mutex_unlock(mu);
    maildrop_locked = false;
    fp = NULL;
    fd = -1;
    mu = NULL;
  }
  // Cleanup when client disconnects normally
  remove_client(comm_fd);
  close(comm_fd);
  return NULL;
}
static pthread_mutex_t *get_mbox_mutex(const char *path)
{
  pthread_mutex_lock(&mbox_lock_table_mu);

  int free_idx = -1;

  for (int i = 0; i < MAX_MBOX_LOCKS; i++)
  {
    if (mbox_lock_table[i].used)
    {
      // If this slot is already for the same mailbox path, return its mutex
      if (strncmp(mbox_lock_table[i].path, path, MBOX_PATH_LEN) == 0)
      {
        pthread_mutex_t *ret = &mbox_lock_table[i].mu;
        pthread_mutex_unlock(&mbox_lock_table_mu);
        return ret;
      }
    }
    else if (free_idx == -1)
    {
      // Remember the first free slot, but keep looping
      // in case we find an existing matching path later
      free_idx = i;
    }
  }

  // if no existing mutex found, create one in the first free slot
  if (free_idx != -1)
  {
    mbox_lock_table[free_idx].used = true;

    strncpy(mbox_lock_table[free_idx].path, path, MBOX_PATH_LEN - 1);
    mbox_lock_table[free_idx].path[MBOX_PATH_LEN - 1] = '\0';

    pthread_mutex_init(&mbox_lock_table[free_idx].mu, NULL);

    pthread_mutex_t *ret = &mbox_lock_table[free_idx].mu;
    pthread_mutex_unlock(&mbox_lock_table_mu);
    return ret;
  }

  // table full
  pthread_mutex_unlock(&mbox_lock_table_mu);
  return NULL;
}
static int append_bytes(char **buf, size_t *len, size_t *cap, const char *src, size_t n)
{
  // Grow buffer if needed
  if (*len + n > *cap)
  {
    size_t new_cap = (*cap == 0) ? 256 : *cap;
    while (*len + n > new_cap)
      new_cap *= 2;

    char *tmp = (char *)realloc(*buf, new_cap);
    if (tmp == NULL)
      return -1;

    *buf = tmp;
    *cap = new_cap;
  }
  // Append raw bytes
  memcpy(*buf + *len, src, n);
  *len += n;
  return 0;
}

static int compute_uidl_for_msg(FILE *mail_fp, int msg_no, char uid_hex_out[33])
{
  if (mail_fp == NULL || msg_no <= 0)
    return -1;

  rewind(mail_fp);

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread;

  int curr_msg_no = 0;
  int in_target = 0;

  char *msg_buf = NULL;
  size_t msg_len = 0, msg_cap = 0;

  while ((nread = getline(&line, &cap, mail_fp)) != -1)
  {
    if (strncmp(line, "From ", 5) == 0)
    {
      curr_msg_no++;

      if (in_target)
        break; // next message starts => target complete

      if (curr_msg_no == msg_no)
        in_target = 1;
    }

    if (!in_target)
      continue;

    // Hash raw mbox bytes, including the "From ...\n" separator line,
    // exactly as read by getline (do NOT strip newline, do NOT CRLF-normalize)
    if (append_bytes(&msg_buf, &msg_len, &msg_cap, line, (size_t)nread) != 0)
    {
      free(msg_buf);
      free(line);
      return -2; // OOM
    }
  }

  free(line);

  if (!in_target)
  {
    free(msg_buf);
    return -1; // not found
  }

  if (msg_len > (size_t)INT_MAX)
  {
    free(msg_buf);
    return -3; // too large for computeDigest(int)
  }

  unsigned char digest[MD5_DIGEST_LENGTH];
  // Hash full raw message
  computeDigest(msg_buf, (int)msg_len, digest);
  digestToHex(digest, uid_hex_out);

  free(msg_buf);
  return 0;
}
static int apply_deletions_to_mbox(FILE *mail_fp,
                                   const char *mailbox_path,
                                   const int *msg_deleted,
                                   size_t msg_count_total)
{
  if (mail_fp == NULL || mailbox_path == NULL || msg_deleted == NULL)
    return -1;

  rewind(mail_fp);
  // Create temporary file in same directory (required for atomic rename)
  char tmp_path[1200];
  snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", mailbox_path);

  FILE *out = fopen(tmp_path, "w");
  if (out == NULL)
    return -2;

  char *line = NULL;
  size_t cap = 0;
  ssize_t nread;

  size_t curr_msg_no = 0; // 1-based message numbering in mbox parse
  int in_message = 0;
  int keep_current = 0;
  // mbox message boundary
  while ((nread = getline(&line, &cap, mail_fp)) != -1)
  {
    // Detect new message boundary
    if (strncmp(line, "From ", 5) == 0)
    {
      curr_msg_no++;
      in_message = 1;

      // Safety check: mailbox changed unexpectedly since PASS parse
      if (curr_msg_no > msg_count_total)
      {
        free(line);
        fclose(out);
        remove(tmp_path);
        return -3;
      }

      keep_current = (msg_deleted[curr_msg_no - 1] == 0);
    }

    // Copy exact raw mbox bytes for undeleted messages
    if (in_message && keep_current)
    {
      if (fwrite(line, 1, (size_t)nread, out) != (size_t)nread)
      {
        free(line);
        fclose(out);
        remove(tmp_path);
        return -4;
      }
    }
  }

  free(line);
  // Flush stdio buffer
  if (fflush(out) != 0)
  {
    fclose(out);
    remove(tmp_path);
    return -5;
  }
  // Force kernel write to disk (durability)
  int out_fd = fileno(out);
  if (out_fd >= 0)
    fsync(out_fd); // optional but good

  if (fclose(out) != 0)
  {
    remove(tmp_path);
    return -6;
  }

  // Atomically replace original mailbox (same filesystem)
  if (rename(tmp_path, mailbox_path) != 0)
  {
    remove(tmp_path);
    return -7;
  }

  return 0;
}
void handle_sigint(int sig)
{
  // Set flag to stop accept loop and close listen_fd
  (void)sig;
  keep_running = 0;
  close(listen_fd);
}