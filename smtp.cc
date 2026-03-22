#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <strings.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <stdbool.h>
#include <getopt.h>
#include <time.h>
#include <sys/file.h>
#define MAX_CLIENTS 100

#define BUF_SIZE 4096

#define MAX_RCPTS 100
#define RCPT_LEN 256

#define MAX_MBOX_LOCKS 512
#define MBOX_PATH_LEN 1024

typedef struct
{
  bool used;
  char path[MBOX_PATH_LEN];
  pthread_mutex_t mu;
} mbox_lock_entry_t;

// mutex locks
static mbox_lock_entry_t mbox_lock_table[MAX_MBOX_LOCKS];
static pthread_mutex_t mbox_lock_table_mu = PTHREAD_MUTEX_INITIALIZER;

bool verbose = false;
int listen_fd;
volatile sig_atomic_t keep_running = 1;

static int clients[MAX_CLIENTS];
static int client_count = 0;
static pthread_mutex_t clients_mu = PTHREAD_MUTEX_INITIALIZER;

const char *maildir = NULL;

// function prototypes
void handle_sigint(int sig);
void *worker(void *arg);
static void handle_data_line(
    int comm_fd, const char *line, bool *in_data,
    char **message_buf, size_t *message_len, size_t *message_cap,
    const char *mail_from,
    char rcpt_list[MAX_RCPTS][RCPT_LEN],
    int *rcpt_count,
    const char *maildir,
    bool *mail_from_set);

static pthread_mutex_t *get_mbox_mutex(const char *path);

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
  // SIGINT -> graceful shutdown
  // SIGPIPE ignored to prevent crash on client disconnect
  signal(SIGINT, handle_sigint);
  signal(SIGPIPE, SIG_IGN);
  int port = 2500;
  int opt;

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
  struct sockaddr_in servaddr;
  bzero(&servaddr, sizeof(servaddr));
  servaddr.sin_family = AF_INET; // ipv4
  servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

  while ((opt = getopt(argc, argv, "p:av")) != -1)
  {
    switch (opt)
    {
    case 'p':
      port = atoi(optarg);
      break;
    case 'v':
      verbose = true;
      break;
    case 'a':
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
  if (bind(listen_fd, (struct sockaddr *)&servaddr, sizeof(servaddr)))
  {
    perror("bind");
    close(listen_fd);
    exit(1);
  }
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
    int *client_fd = (int *)malloc(sizeof(int));
    if (!client_fd)
    {
      perror("malloc");
      continue;
    }
    *client_fd = accept(listen_fd, (struct sockaddr *)&clientaddr, &clientaddrlen);

    if (*client_fd < 0)
    {
      int err = errno;
      free(client_fd);
      if (!keep_running)
        break;
      if (err == EINTR)
        continue;
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
    if (pthread_create(&thread, NULL, worker, client_fd) != 0)
    {
      perror("pthread_create");
      close(*client_fd);
      free(client_fd);
      continue;
    }
    pthread_detach(thread);
  }
  // In case of interruption
  const char *msg = "421 localhost Service not available, closing transmission channel\r\n";
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

void handle_sigint(int sig)
{
  // Set flag to stop accept loop and close listen_fd
  (void)sig;
  keep_running = 0;
  close(listen_fd);
}

void *worker(void *arg)
{
  int comm_fd = *(int *)arg;
  free(arg);

  add_client(comm_fd);
  const char *greet = "220 localhost Service Ready\r\n";
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

  bool greeted = false;       // for HELO
  bool mail_from_set = false; // for mail from
  int rcpt_count = 0;         // to keep a count of recipients

  bool in_data = false;
  size_t message_len = 0;
  size_t message_cap = 4096;
  char mail_from[BUF_SIZE];
  char *message_buf = (char *)malloc(message_cap);
  if (!message_buf)
  {
    remove_client(comm_fd);
    close(comm_fd);
    return NULL;
  }
  message_buf[0] = '\0';
  char rcpt_list[MAX_RCPTS][RCPT_LEN];
  char rcpt_user[RCPT_LEN];
  while (true)
  {
    if (len >= BUF_SIZE - 1)
    {
      const char *resp = "500 Syntax error, command unrecognized\r\n";
      if (verbose)
        fprintf(stderr, "[%d] S: %s", comm_fd, resp);
      write(comm_fd, resp, strlen(resp));
      break;
    }
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

    while ((line_end = strstr(buf, "\r\n")) != NULL)
    {

      *line_end = '\0';
      char *cmd = buf;

      if (verbose)
      {
        fprintf(stderr, "[%d] C: %s\n", comm_fd, cmd);
      }
      if (in_data)
      {
        handle_data_line(comm_fd, cmd, &in_data, &message_buf, &message_len, &message_cap,
                         mail_from, rcpt_list, &rcpt_count, maildir, &mail_from_set);
        goto consume;
      }
      else
      {
        // 1. HELO command
        if (strncasecmp(cmd, "HELO", 4) == 0)
        {
          // to check if in initial state(for consecutive HELOs)
          bool initial_state = (!mail_from_set && rcpt_count == 0 && !in_data);
          if (cmd[4] != ' ' || cmd[5] == '\0')
          {
            resp = "501 Syntax error in parameters or arguments\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else if (!initial_state)
          {
            resp = "503 Bad sequence of commands\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else
          {
            greeted = true;
            resp = "250 localhost\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            // sender SMTP and the receiver SMTP are in the initial state
            // all state tables and buffered are clear
            mail_from_set = false;
            rcpt_count = 0;
            in_data = false;
            mail_from[0] = '\0';
            message_len = 0;
            message_buf[0] = '\0';
            memset(rcpt_list, 0, sizeof(rcpt_list));
            goto consume;
          }
        }

        // 2. MAIL FROM command
        else if (strncasecmp(cmd, "MAIL FROM:", 10) == 0)
        {
          const char *p = cmd + 10;
          while (*p == ' ')
            p++;
          if (*p != '<')
          {
            resp = "501 Syntax error in parameters or arguments\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume; // jump to shifting logic
          }

          const char *lt = p;
          const char *gt = strchr(lt, '>');
          // checking <> are closed
          if (!gt || gt[1] != '\0')
          {
            resp = "501 Syntax error in parameters or arguments\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          size_t addr_len = (size_t)(gt - (lt + 1));
          if (addr_len >= sizeof(mail_from))
          {
            resp = "503 Command length too long\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          if (addr_len == 0)
          {
            const char *resp = "501 Syntax error in parameters or arguments\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          // HELO is required first
          if (!greeted)
          {
            const char *resp = "503 Bad sequence of commands\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          // all state tables and buffered are clear

          message_len = 0;
          message_buf[0] = '\0';
          rcpt_count = 0;
          memset(rcpt_list, 0, sizeof(rcpt_list));
          memcpy(mail_from, lt + 1, addr_len);
          mail_from[addr_len] = '\0';
          mail_from_set = true;

          const char *resp = "250 OK\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }

        // 3. RCPT TO command
        else if (strncasecmp(cmd, "RCPT TO:", 8) == 0)
        {
          if (!greeted)
          {
            resp = "503 Bad sequence of commands\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else if (!mail_from_set)
          {
            const char *resp = "503 Bad sequence of commands\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else
          {
            const char *u = cmd + 8;
            while (*u == ' ')
              u++;
            if (*u != '<')
            {
              resp = "501 Syntax error in parameters or arguments\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }

            const char *lt = u;
            const char *gt = strchr(lt, '>');
            const char *at = strchr(lt, '@');

            if (!gt || !at || at > gt || gt[1] != '\0')
            {
              resp = "501 Syntax error in parameters or arguments\r\n";
              if (verbose)
                fprintf(stderr, "[%d] S: %s", comm_fd, resp);
              write(comm_fd, resp, strlen(resp));
              goto consume;
            }
            else
            {
              char dom[128];
              size_t dom_len = (size_t)(gt - (at + 1));
              if (dom_len >= sizeof(dom))
                dom_len = sizeof(dom) - 1;
              memcpy(dom, at + 1, dom_len);
              dom[dom_len] = '\0';

              if (strcasecmp(dom, "localhost") != 0)
              {
                resp = "550 No such user here\r\n";
                if (verbose)
                  fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                write(comm_fd, resp, strlen(resp));
                goto consume;
              }

              else
              {
                // username = text after '<' up to '@'
                size_t user_len = (size_t)(at - (lt + 1));
                if (user_len == 0 || user_len >= sizeof(rcpt_user))
                {
                  resp = "501 Syntax error in parameters or arguments\r\n";
                  if (verbose)
                    fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                  write(comm_fd, resp, strlen(resp));
                  goto consume;
                }
                else
                {
                  memcpy(rcpt_user, lt + 1, user_len);
                  rcpt_user[user_len] = '\0';

                  char path[1024];
                  snprintf(path, sizeof(path), "%s/%s.mbox", maildir, rcpt_user);

                  // checking if the mailbox exists
                  if (access(path, F_OK) != 0)
                  {
                    resp = "550 No such user here\r\n";
                    if (verbose)
                      fprintf(stderr, "[%d] S: %s", comm_fd, resp, maildir, rcpt_user);
                    write(comm_fd, resp, strlen(resp));
                    goto consume;
                  }

                  // maximum number of recipients reached
                  if (rcpt_count == MAX_RCPTS)
                  {
                    resp = "452 Too many recipients\r\n";
                    if (verbose)
                      fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                    write(comm_fd, resp, strlen(resp));
                    goto consume;
                  }
                  else
                  {
                    strncpy(rcpt_list[rcpt_count], rcpt_user, RCPT_LEN - 1);
                    rcpt_list[rcpt_count][RCPT_LEN - 1] = '\0';
                    rcpt_count++;
                    resp = "250 OK\r\n";
                    if (verbose)
                      fprintf(stderr, "[%d] S: %s", comm_fd, resp);
                    write(comm_fd, resp, strlen(resp));
                    goto consume;
                  }
                }
              }
            }
          }
        }

        // 4. DATA
        else if (strcasecmp(cmd, "DATA") == 0)
        {
          // checking if sequence of commands are being followed
          if (!greeted)
          {
            resp = "503 Bad sequence of commands\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          if (!mail_from_set)
          {
            resp = "503 Bad sequence of commands\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          if (rcpt_count == 0)
          {
            resp = "503 Bad sequence of commands\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          resp = "354 Start mail input; End data with <CRLF>.<CRLF>\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));

          in_data = true;
          message_buf[0] = '\0';
          message_len = 0;
          goto consume;
        }

        // 5. QUIT
        // QUIT closes the session and cleans up state.
        else if (strcasecmp(cmd, "QUIT") == 0)
        {
          resp = "221 localhost Service closing transmission channel\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));

          // clear state
          mail_from_set = false;
          rcpt_count = 0;
          in_data = false;
          mail_from[0] = '\0';
          message_len = 0;
          if (message_buf)
            message_buf[0] = '\0';
          memset(rcpt_list, 0, sizeof(rcpt_list));

          close(comm_fd);
          if (verbose)
            fprintf(stderr, "[%d] Connection closed\n", comm_fd);

          remove_client(comm_fd);
          free(message_buf);
          return NULL;
        }

        // 6. RSET
        else if (strcasecmp(cmd, "RSET") == 0)
        {
          if (!greeted)
          {
            resp = "503 Bad sequence of commands\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
          else
          {
            mail_from_set = false;
            rcpt_count = 0;
            in_data = false;
            mail_from[0] = '\0';
            message_len = 0;
            message_buf[0] = '\0';
            memset(rcpt_list, 0, sizeof(rcpt_list));

            resp = "250 OK\r\n";
            if (verbose)
              fprintf(stderr, "[%d] S: %s", comm_fd, resp);
            write(comm_fd, resp, strlen(resp));
            goto consume;
          }
        }

        // NOOP
        else if (strcasecmp(cmd, "NOOP") == 0)
        {
          resp = "250 OK\r\n";
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          write(comm_fd, resp, strlen(resp));
          goto consume;
        }

        else
        {
          resp = "500 Syntax error, command unrecognized\r\n";
          write(comm_fd, resp, strlen(resp));
          if (verbose)
            fprintf(stderr, "[%d] S: %s", comm_fd, resp);
          goto consume;
        }
      }

    consume:
      char *next_data = line_end + 2; // line_end points to \r , +2 will point to the next data
      int remaining_len = len - (next_data - buf);
      memmove(buf, next_data, remaining_len); // shifting data to the front of buffer
      len = remaining_len;
      buf[len] = '\0';
      continue;
    }
  }
  remove_client(comm_fd);
  close(comm_fd);
  free(message_buf);
  return NULL;
}

static void handle_data_line(int comm_fd, const char *line, bool *in_data, char **message_buf, size_t *message_len, size_t *message_cap,
                             const char *mail_from, char rcpt_list[MAX_RCPTS][RCPT_LEN], int *rcpt_count, const char *maildir, bool *mail_from_set)
{
  // Handles lines received during DATA mode.
  // Accumulates message body until "." is received.
  int delivered_count = 0;
  // A single "." indicates end of DATA.
  if (strcmp(line, ".") == 0)
  {
    time_t now = time(NULL);
    char ds[32];
    if (ctime_r(&now, ds) == NULL)
    {
      const char *r451 = "451 Requested action aborted: local error in processing\r\n";
      write(comm_fd, r451, strlen(r451));
      if (verbose)
        fprintf(stderr, "[%d] S: %s", comm_fd, r451);

      *in_data = false;
      *message_len = 0;
      (*message_buf)[0] = '\0';
      *mail_from_set = false;
      *rcpt_count = 0;
      return;
    }

    // Finish DATA mode
    *in_data = false;

    for (int i = 0; i < *rcpt_count; i++)
    {
      char path[1024];
      snprintf(path, sizeof(path), "%s/%s.mbox", maildir, rcpt_list[i]);
      pthread_mutex_t *mu = get_mbox_mutex(path);

      if (mu == NULL)
      {
        continue;
      }

      pthread_mutex_lock(mu); // locking mutex

      FILE *fp = fopen(path, "a");
      if (!fp)
      {
        pthread_mutex_unlock(mu);
        continue;
      }
      // to prohibit different programs from accessing the same mailbox at the same time
      int fd = fileno(fp);
      if (flock(fd, LOCK_EX) != 0)
      {
        fclose(fp);
        pthread_mutex_unlock(mu);
        continue;
      }

      int write_failed = 0;
      // checks for fails

      if (fprintf(fp, "From <%s> %s", mail_from, ds) < 0)
        write_failed = 1;

      if (!write_failed && fwrite(*message_buf, 1, *message_len, fp) != *message_len)
        write_failed = 1;

      if (!write_failed && fflush(fp) != 0)
        write_failed = 1;

      flock(fd, LOCK_UN); // unlocking flock
      fclose(fp);
      pthread_mutex_unlock(mu); // unlocking mutex

      if (write_failed)
      {
        continue;
      }
      delivered_count++;
    }
    if (delivered_count > 0)
    {
      const char *r250 = "250 OK\r\n";
      write(comm_fd, r250, strlen(r250));
      if (verbose)
        fprintf(stderr, "[%d] S: %s", comm_fd, r250);
    }
    else
    {
      const char *r451 = "451 Requested action aborted: local error in processing\r\n";
      write(comm_fd, r451, strlen(r451));
      if (verbose)
        fprintf(stderr, "[%d] S: %s", comm_fd, r451);
    }

    // Reset transaction state (always after ".")
    *message_len = 0;
    (*message_buf)[0] = '\0';
    *mail_from_set = false;
    *rcpt_count = 0;
    return;
  }

  size_t L = strlen(line);
  size_t needed = *message_len + L + 2 + 1; // line + CRLF + '\0'
  if (needed > *message_cap)
  {
    size_t new_cap = *message_cap;
    while (new_cap < needed)
      new_cap *= 2;

    char *new_buf = (char *)realloc(*message_buf, new_cap);
    if (!new_buf)
    {
      const char *r451 = "451 Requested action aborted: local error in processing\r\n";
      write(comm_fd, r451, strlen(r451));
      if (verbose)
        fprintf(stderr, "[%d] S: %s", comm_fd, r451);

      *in_data = false;
      *message_len = 0;
      (*message_buf)[0] = '\0';
      *mail_from_set = false;
      *rcpt_count = 0;
      return;
    }

    *message_buf = new_buf;
    *message_cap = new_cap;
  }

  memcpy(*message_buf + *message_len, line, L);
  *message_len += L;
  (*message_buf)[(*message_len)++] = '\r';
  (*message_buf)[(*message_len)++] = '\n';
  (*message_buf)[*message_len] = '\0';
}

// Returns a mutex corresponding to a mailbox path.
// If none exists, creates one in the global lock table.
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