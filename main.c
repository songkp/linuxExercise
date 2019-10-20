#include "sysutil.h"
#include "session.h"
#include "parseconf.h"
#include "tunable.h"
int main(void)
{
	parseconf_load_file("miniftpd.conf");
	printf("tunable_pasv_enable=%d\n", tunable_pasv_enable);
	printf("tunable_port_enable=%d\n", tunable_port_enable);
	printf("tunable_listen_address=%s\n", tunable_listen_address);
	if(getuid() != 0)
	{
		fprintf(stderr, "must be started as root \n");
		exit(EXIT_FAILURE);
	}

	session_t sess = 
	{
		0,-1, "","","",
		-1,-1,0
	};

	int listenfd = tcp_server(NULL,5188);
	printf("listenfd = %d\n",listenfd);
	int conn;
	pid_t pid;
	
	while(1)
	{
		conn = accept_timeout(listenfd, NULL,0);
		if(conn == -1)
			ERR_EXIT("accept_timeout");

		pid = fork();
		if(pid == -1)
		{
			ERR_EXIT("fork");
		}

		if(pid == 0)
		{
			 printf(" --------accept --- pid = %d\n",pid);
			close(listenfd);
			sess.ctrl_fd = conn;
			begin_session(&sess);
		}
		else
			close(conn);
	}

	return 0;
}
