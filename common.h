#ifndef _COMMON_H_
#define _COMMON_H_

#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <crypt.h>
#include <shadow.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>


#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/time.h>

#define ERR_EXIT(m) \
  do \
  { \
    perror(m); \
    exit(EXIT_FAILURE); \
  } \
  while (0)
#define MAX_COMMAND_LINE 1024
#define MAX_COMMAND 32
#define MAX_ARG 1024

#endif /* _COMMON_H_ */
