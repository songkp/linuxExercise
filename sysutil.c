#include "sysutil.h"

/**
 * tcp_client -??????tcp???,???????
 * @port : ???????,??0????????,??0???????????
 * ?????????
 */

int tcp_client(unsigned short port)
{
    int sock;
    if ((sock = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        ERR_EXIT("TCP_CLIENT");
    }

    if (port > 0)
    {
        int on = 1;
        if(setsockopt(sock, SOL_SOCKET,SO_REUSEADDR, (const char*)&on, sizeof(on))< 0)
        {
            ERR_EXIT("setsockopt");
        }
        char ip[15] = {0};
        getlocalip(ip);
        struct sockaddr_in localaddr;
        memset(&localaddr, 0, sizeof(localaddr));
        localaddr.sin_family = AF_INET;
        localaddr.sin_port = htons(port);
        localaddr.sin_addr.s_addr = inet_addr(ip);
        if((bind(sock, (struct sockaddr*)&localaddr, sizeof(localaddr))) < 0)
        {
            ERR_EXIT("bind");
        }
    }
    return sock;
}


/**
 * tcp_server -??????tcp???
 * @host : ?????????ip??
 * @port : ???????
 * ?????????
 */
int tcp_server(const char *host, unsigned short port)
{
    int listenfd;
    if ((listenfd = socket(PF_INET, SOCK_STREAM, 0)) < 0)
    {
        ERR_EXIT("TCP_SERVER");
    }
    
    struct sockaddr_in seraddr;
    memset(&seraddr, 0, sizeof(seraddr));
    seraddr.sin_family = AF_INET;
    if(host != NULL)
    {
        if (inet_aton(host, &seraddr.sin_addr) == 0)
        {
            struct hostent *hp;
            if((hp = gethostbyname(host)) == NULL)
            {
                ERR_EXIT("gethostbyname");
            }
            seraddr.sin_addr  = *(struct in_addr*)hp->h_addr;
        }
    }
    else
    {
        seraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    seraddr.sin_port = htons(port);
    int on = 1;
    if(setsockopt(listenfd, SOL_SOCKET,SO_REUSEADDR, (const char*)&on, sizeof(on))< 0)
    {
        ERR_EXIT("setsockopt");
    }
    if((bind(listenfd, (struct sockaddr*)&seraddr, sizeof(seraddr))) < 0)
    {
        ERR_EXIT("bind");
    }
    if((listen(listenfd, SOMAXCONN)) < 0)
    {
        ERR_EXIT("listen");
    }

    return listenfd;
}


/**
*getlocalip ????ip??, ?????-1??????,????0??????
*@ip  ????ip???
*/
int getlocalip(char *ip)
{


    char host[100] = {0};
    if (gethostname(host, sizeof(host))< 0)     //????host?name
        return -1;
    struct hostent *hp;
    /*
             struct hostent
             {
             char * h_name; / *???????* /
             char ** h_aliases; / *????* /
             int h_addrtype; / *??????* /
             int h_length; / *????* /
             char ** h_addr_list; / *????* /
             };
             #define h_addr h_addr_list [0]
    */
    if ((hp = gethostbyname(host)) == NULL)     //????hostname??????
        return -1;

    strcpy(ip, inet_ntoa(*(struct in_addr *)hp->h_addr));
        return 0;

}


/**
 * activate_noblock - ??I/O??????
 * @fd: ?????
 */
void activate_nonblock(int fd)
{
    int ret;
    int flag = fcntl(fd, F_GETFL);  //??????
    if (flag == -1)
        ERR_EXIT("fcntl");
    
    flag |= O_NONBLOCK;
    ret = fcntl(fd, F_SETFL);     //??????
    if (ret == -1)
        ERR_EXIT("fcntl");
}

/**
 * deactivate_nonblock - ??I/O?????
 * @fd: ?????
 */
void deactivate_nonblock(int fd)
{
    int ret;
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1)
        ERR_EXIT("fcntl");
    
    flags &= ~O_NONBLOCK;
    ret = fcntl(fd, F_SETFL);
    if (ret == -1)
         ERR_EXIT("fcntl");
    
}

/**
 * read_timeout - ???????,?????
 * @fd: ?????
 * @wait_seconds: ??????,???0???????
 * ??(???)??0,????-1,????-1??errno = ETIMEDOUT
 * ????select??
 */
int read_timeout(int fd, unsigned int wait_seconds)
{
    int ret = 0;
    if (wait_seconds > 0)
    {    fd_set fds;
        struct timeval timeout;

        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do
        {
            ret = select(fd + 1, &fds, NULL, NULL, &timeout);
        }while(ret == -1 && errno == EINTR);

		if (ret == 0) {
			ret = -1;
			errno = ETIMEDOUT;
		}
        if (ret == 1)
        {
            ret = 0;
        }
    }   
    return ret;
}
/**
 * write_timeout - ???????,?????
 * @fd: ?????
 * @wait_seconds: ??????,???0???????
 * ??(???)??0,????-1,????-1??errno = ETIMEDOUT
 */
int write_timeout(int fd, unsigned int wait_seconds)
{
        int ret = 0;
    if (wait_seconds > 0)
    {    fd_set fds;
        struct timeval timeout;

        FD_ZERO(&fds);
        FD_SET(fd, &fds);
        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do
        {
            ret = select(fd + 1, NULL, &fds, NULL,  &timeout);
        }while(ret == -1 && errno == EINTR);

		if (ret == 0) {
			ret = -1;
			errno = ETIMEDOUT;
		}
        if (ret == 1)
        {
            ret = 0;
        }
    }   
    return ret;
}
/**
 * accept_timeout - ????accept
 * @fd: ???
 * @addr: ????,??????
 * @wait_seconds: ??????,???0??????
 * ??(???)????????,????-1??errno = ETIMEDOUT
 * ??io???select??
 */
int accept_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
    int ret;
    socklen_t socklen = sizeof(struct sockaddr_in);

    if (wait_seconds > 0)
    {
        fd_set accpfds;
        struct timeval waittime;

        FD_ZERO(&accpfds);
        FD_SET(fd, &accpfds);

        waittime.tv_sec = wait_seconds;
        waittime.tv_usec = 0;

        do
        {
            ret = select(fd + 1, &accpfds, NULL, NULL, &waittime);
        }while(ret < 0 && errno == EINTR);

        if (ret == 0)
        {
            errno = ETIMEDOUT;
            return -1;
        }
   }

    if(addr == NULL)
    {
        ret = accept(fd, NULL, NULL);
    }
    else
    {
        ret = accept(fd, (struct sockaddr*)addr, &socklen);
    }
    return ret;
}


/**
 * connect_timeout - connect
 * @fd: ???
 * @addr: ????????
 * @wait_seconds: ??????,???0??????
 * ??(???)??0,????-1,????-1??errno = ETIMEDOUT
 * ??io???select??
 */
int connect_timeout(int fd, struct sockaddr_in *addr, unsigned int wait_seconds)
{
    int ret;
    socklen_t socklen = sizeof(struct sockaddr_in);

    if (wait_seconds > 0)
        activate_nonblock(fd);
    
    ret = connect(fd, (struct sockaddr *)addr, socklen);
    if (ret < 0 && errno == EINPROGRESS)
    {
        fd_set connfds;
        struct timeval timeout;
        
        FD_ZERO(&connfds);
        FD_SET(fd, &connfds);

        timeout.tv_sec = wait_seconds;
        timeout.tv_usec = 0;
        do
        {
            ret = select(fd + 1, NULL, &connfds, NULL, &timeout);
        }while(ret < 0 && errno == EINTR);

        if (ret == 0)
        {
            errno = ETIMEDOUT;
            return -1;
        }
        else if (ret < 0)
        {
            return -1;
        }
        else if(ret == 1)
        {
            /* ret???1,???????,?????????,??????????,*/
			/* ???????????errno???,??,????getsockopt???? */
            int err;
            socklen_t len = sizeof(err);
            int sockopt = getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len);
            if (sockopt == -1)
            {
                return -1;
            }
            if (err == 0)
            {
                ret = 0;
            }
            else
            {
                ret = -1;
                errno = err;
            }
        }
    }
    if (wait_seconds > 0)
    {
        deactivate_nonblock(fd);
    }
    return ret;
}

/**
 * readn - ???????
 * @fd: ?????
 * @buf: ?????
 * @count: ???????
 * ????count,????-1,??EOF??<count
 */
ssize_t readn(int fd, void* buf, size_t count)
{
    ssize_t nleft = count;
    ssize_t nread;
    char *bufp = (char *)buf;
    while(nleft > 0)
    {
        nread = read(fd, bufp, nleft);
        if (nread < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        else if (nread == 0)
        {
            return count - nleft;
        }

        nleft -= nread;
        bufp += nread;
    }
    return count;
}

/**
 * writen - ???????
 * @fd: ?????
 * @buf: ?????
 * @count: ???????
 * ????count,????-1
 */
ssize_t writen(int fd, const void* buf, size_t count)
{
    ssize_t nleft = count;
    ssize_t nwriten;
    char *bufp = (char *)buf;
    while(nleft > 0)
    {
        nwriten = write(fd, buf, nleft);
        if (nwriten < 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            return -1;
        }
        if (nwriten == 0)
        {
            return count - nleft;
        }

        nleft -= nwriten;
        bufp += nwriten;
    }
    return count;
}

/**
 * recv_peek - ????????????,??????
 * @sockfd: ???
 * @buf: ?????
 * @len: ??
 * ????>=0,????-1
 */
ssize_t recv_peek(int sockfd, void *buf, size_t len)
{
	while (1) 
    {
		int ret = recv(sockfd, buf, len, MSG_PEEK);
		if (ret == -1 && errno == EINTR)
			continue;
		return ret;
	}
}

/**
 * readline - ??????
 * @sockfd: ???
 * @buf: ?????
 * @maxline: ??????
 * ????>=0,????-1
 */
ssize_t readline(int sockfd, void *buf, size_t maxline)
{
	int ret;
	int nread;
	char *bufp = (char *)buf;
	int nleft = maxline;
	while (1) 
    {
		ret = recv_peek(sockfd, bufp, nleft);
		if (ret < 0)
			return ret;
		else if (ret == 0)
			return ret;

		nread = ret;
		int i;
		for (i=0; i<nread; i++) 
        {
			if (bufp[i] == '\n') 
            {
				ret = readn(sockfd, bufp, i+1);
				if (ret != i+1)
					exit(EXIT_FAILURE);

				return ret;
			}
		}

		if (nread > nleft)
			exit(EXIT_FAILURE);

		nleft -= nread;
		ret = readn(sockfd, bufp, nread);
		if (ret != nread)
			exit(EXIT_FAILURE);
		bufp += nread;
	}

	return -1;
}

/**
 * send_fd -?sock_fd ?? fd
 * @sock_fd: ???????
 * @fd: ?????
 */
void send_fd(int sock_fd, int fd)
{
    int ret;
    struct msghdr msg;
    struct cmsghdr *p_cmsg;
    struct iovec vec;
    char cmsgbuf[CMSG_SPACE(sizeof(fd))];
    int *p_fds;
    char sendchar = 0;
    msg.msg_control = cmsgbuf;
    msg.msg_controllen = sizeof(cmsgbuf);
    p_cmsg = CMSG_FIRSTHDR(&msg);
	p_cmsg->cmsg_level = SOL_SOCKET;
	p_cmsg->cmsg_type = SCM_RIGHTS;
	p_cmsg->cmsg_len = CMSG_LEN(sizeof(fd));
	p_fds = (int*)CMSG_DATA(p_cmsg);
	*p_fds = fd;

	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_flags = 0;

	vec.iov_base = &sendchar;
	vec.iov_len = sizeof(sendchar);
	ret = sendmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("sendmsg");
}

/**
 * send_fd -?sock_fd ?? fd
 * @sock_fd: ???????
 * ???????
 */
int recv_fd(const int sock_fd)
{
    int ret;
	struct msghdr msg;
	char recvchar;
	struct iovec vec;
	int recv_fd;
	char cmsgbuf[CMSG_SPACE(sizeof(recv_fd))];
	struct cmsghdr *p_cmsg;
	int *p_fd;
	vec.iov_base = &recvchar;
	vec.iov_len = sizeof(recvchar);
	msg.msg_name = NULL;
	msg.msg_namelen = 0;
	msg.msg_iov = &vec;
	msg.msg_iovlen = 1;
	msg.msg_control = cmsgbuf;
	msg.msg_controllen = sizeof(cmsgbuf);
	msg.msg_flags = 0;

	p_fd = (int*)CMSG_DATA(CMSG_FIRSTHDR(&msg));
	*p_fd = -1;  
	ret = recvmsg(sock_fd, &msg, 0);
	if (ret != 1)
		ERR_EXIT("recvmsg");

	p_cmsg = CMSG_FIRSTHDR(&msg);
	if (p_cmsg == NULL)
		ERR_EXIT("no passed fd");


	p_fd = (int*)CMSG_DATA(p_cmsg);
	recv_fd = *p_fd;
	if (recv_fd == -1)
		ERR_EXIT("no passed fd");

	return recv_fd;
}
