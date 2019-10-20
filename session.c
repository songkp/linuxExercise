#include "common.h"
#include "session.h"
#include "privparent.h"
#include "ftpproto.h"
#include "sysutil.h"


void begin_session(session_t *sess)
{
	/* struct passwd *pw = getpwnam("nobody");
		if(pw == NULL)
			return;
		if(setegid(pw->pw_gid)< 0)
			ERR_EXIT("setegid");
		if(seteuid(pw->pw_uid) < 0)
			ERR_EXIT("seteuid"); */
	
	int sockfds[2];
	if(socketpair(PF_UNIX,SOCK_STREAM, 0, sockfds)<0)
		ERR_EXIT("socketpair");
	
	printf("----00---pid=%d\n",getpid());	
	pid_t pid;
	pid = fork();
	if (pid < 0)
		ERR_EXIT("fork");

	if (pid == 0) 
    {
		close(sockfds[0]);
		printf("pid = %d,func = %s \n",getpid(), __FILE__);
		sess->child_fd = sockfds[1];
		handle_child(sess);
	} 
    else 
    {
		struct passwd *pw = getpwnam("nobody");
		if(pw == NULL)
			return;
		if(setegid(pw->pw_gid)< 0)
			ERR_EXIT("setegid");
		if(seteuid(pw->pw_uid) < 0)
			ERR_EXIT("seteuid");
	
 		printf("pid = %d,func = %s \n",getpid(), __FILE__);
		// nobody进程
		close(sockfds[1]);
		sess->parent_fd = sockfds[0];
		printf("into handle_parent\n");
		handle_parent(sess);
	}
}
