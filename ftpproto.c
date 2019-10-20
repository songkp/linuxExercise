#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcode.h"
#include "tunable.h"

#include <dirent.h>
#include <sys/stat.h>

#include <time.h>

//int list_common(session_t *sess, int detail);

static void ftp_reply(session_t *sess, int status, const char *text);
static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
// static void do_port(session_t *sess);
// static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
// static void do_stru(session_t *sess);
// static void do_mode(session_t *sess);
// static void do_retr(session_t *sess);
// static void do_stor(session_t *sess);
// static void do_appe(session_t *sess);
// static void do_list(session_t *sess);
// static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
// static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
// static void do_rmd(session_t *sess);
// static void do_dele(session_t *sess);
// static void do_rnfr(session_t *sess);
// static void do_rnto(session_t *sess);
// static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
// static void do_size(session_t *sess);
// static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);


static void do_site_chmod(session_t *sess, char *chmod_arg);
static void do_site_umask(session_t *sess, char *umask_arg);


typedef struct ftpcmd
{
    const char *cmd;
    void (*cmd_handler)(session_t *sess);
} ftpcmd_t;


static ftpcmd_t ctrl_cmds[] = {
    /* 访问控制命令 */
    {"USER",    do_user    },
    {"PASS",    do_pass    },
    {"CWD",        do_cwd    },
    {"XCWD",    do_cwd    },
    {"CDUP",    do_cdup    },
    {"XCUP",    do_cdup    },
    {"QUIT",    do_quit    },
    // {"ACCT",    NULL    },
    // {"SMNT",    NULL    },
    // {"REIN",    NULL    },
    // /* 传输参数命令 */
    // {"PORT",    do_port    },
    // {"PASV",    do_pasv    },
    {"TYPE",    do_type    },
    // {"STRU",    do_stru    },
    // {"MODE",    do_mode    },

    // /* 服务命令 */
    // {"RETR",    do_retr    },
    // {"STOR",    do_stor    },
    // {"APPE",    do_appe    },
    // {"LIST",    do_list    },
    // {"NLST",    do_nlst    },
    {"REST",    do_rest    },
    // {"ABOR",    do_abor    },
    // {"\377\364\377\362ABOR", do_abor},
    {"PWD",        do_pwd    },
    {"XPWD",    do_pwd    },
    // {"MKD",        do_mkd    },
    // {"XMKD",    do_mkd    },
    // {"RMD",        do_rmd    },
    // {"XRMD",    do_rmd    },
    // {"DELE",    do_dele    },
    // {"RNFR",    do_rnfr    },
    // {"RNTO",    do_rnto    },
    // {"SITE",    do_site    },
    {"SYST",    do_syst    },
    {"FEAT",    do_feat },
    // {"SIZE",    do_size    },
    // {"STAT",    do_stat    },
    {"NOOP",    do_noop    },
    {"HELP",    do_help    },
    {"STOU",    NULL    },
    {"ALLO",    NULL    }
};

void handle_child(session_t *sess)
{
	writen(sess->ctrl_fd, "220 (miniftpd 0.1)\r\n", strlen("220 (miniftpd 0.1)\r\n"));
	while(1)
	{
		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));
		int ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		if(ret == -1)
			ERR_EXIT("readline");
		else if(ret == 0)
			ERR_EXIT("SUCC");
		printf("cmdline =[%s]\n", sess->cmdline);
		str_trim_crlf(sess->cmdline);
		//printf("cmdline = [%s]\n",sess->cmdline);
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		printf("cmd= [%s], arg= [%s]\n", sess->cmd, sess->arg);
		str_upper(sess->cmd);
		/* if(strcmp("USER",sess->cmd) == 0)
			do_user(sess);
		else if(strcmp("PASS",sess->cmd) == 0)
			do_pass(sess); */
		
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
        int i = 0;
        for (i = 0; i < size; i++)
        {
            if (strcmp(sess->cmd, ctrl_cmds[i].cmd) == 0)
            {
                if (ctrl_cmds[i].cmd_handler != NULL)
                {
                    ctrl_cmds[i].cmd_handler(sess);
                }
                else
                {
                    ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
                }
                break;
            }
        }
        if (i == size)
        {
            ftp_reply(sess, FTP_BADCMD, "Unknown command.");
        }
		
	}

}

static void do_user(session_t *sess)
{
	printf("*pw = %s\n",sess->arg);
	struct passwd *pw = getpwnam(sess->arg);
	if(pw == NULL)
	{
		printf("pw == NULL , cfd= %d\n",sess->ctrl_fd);
		char mess[100] = "530 1LOGIN INCORRECT.\r\n";
		writen(sess->ctrl_fd, mess, strlen(mess));
	}
	else	
	{	
		sess->uid = pw->pw_uid;
		ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");		
	}
}

static void do_pass(session_t *sess)
{
	struct passwd *pw = getpwuid(sess->uid);
    if (pw == NULL)
    {
        // 用户不存在
        ftp_reply(sess, FTP_LOGINERR, "2Login incorrect.");
        return;
    }
	
	printf("pw->pw_uid = %d\n",pw->pw_uid);

	printf("name=[%s]\n", pw->pw_name);
	
	struct spwd *sp = getspnam(pw->pw_name);
	if(sp == NULL)
	{			
		ftp_reply(sess, FTP_LOGINERR, "3Login incorrect.");
		return;
	}
	
	char *encrypted = crypt(sess->arg, sp->sp_pwdp);
	
	if(strcmp(encrypted, sp->sp_pwdp) != 0)
	{			
		ftp_reply(sess, FTP_LOGINERR, "4Login incorrect.");
		return;
	}
	
		
	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void ftp_reply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf,"%d %s\r\n",status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

void ftp_lreply(session_t *sess, int status, const char *text)
{
    char buf[1024] = {0};
    sprintf(buf, "%d-%s\r\n",status, text);
    writen(sess->ctrl_fd, buf, strlen(buf));
}

/**
 * 返回０失败，返回１成功。
 */
//int list_common(session_t *sess, int detail)
int list_common(void)
{
    //打开当前目录
    DIR *dir = opendir(".");
    if (dir == NULL)
    {
        return 0;
    }

    //读取目录并进行遍历
    struct dirent *dt;
    struct stat sbuf;
    while ((dt = readdir(dir)) != NULL)
    {    //获取文件的状态
        if (lstat(dt->d_name, &sbuf) < 0)
        {
            continue;
        }
		if (dt->d_name[0] == '.')
        {
            continue;
        }
        char perms[] = "----------";
        perms[0] = '?';
        //获取文件类型
        mode_t mode = sbuf.st_mode;
        switch (mode & S_IFMT)
        {
        case S_IFREG://普通文件
            perms[0] = '-';
            break;
        case S_IFDIR://目录文件
            perms[0] = 'd';
            break;
        case S_IFLNK://链接文件
            perms[0] = 'l';
            break;
        case S_IFIFO://管道文件
            perms[0] = 'p';
            break;
        case S_IFSOCK://套接字文件
            perms[0] = 's';
            break;
        case S_IFCHR://字符设备文件
            perms[0] = 'c';
            break;
        case S_IFBLK://块设备文件
            perms[0] = 'b';
            break;
        }

        //获取文件9个权限位
        if (mode & S_IRUSR)
        {
            perms[1] = 'r';
        }
        if (mode & S_IWUSR)
        {
            perms[2] = 'w';
        }
        if (mode & S_IXUSR)
        {
            perms[3] = 'x';
        }
        if (mode & S_IRGRP)
        {
            perms[4] = 'r';
        }
        if (mode & S_IWGRP)
        {
            perms[5] = 'w';
        }
        if (mode & S_IXGRP)
        {
            perms[6] = 'x';
        }
        if (mode & S_IROTH)
        {
            perms[7] = 'r';
        }
        if (mode & S_IWOTH)
        {
            perms[8] = 'w';
        }
        if (mode & S_IXOTH)
        {
            perms[9] = 'x';
        }
        //获取特珠权限位
        if (mode & S_ISUID)
        {
            perms[3] = (perms[3] == 'x') ? 's' : 'S';
        }
        if (mode & S_ISGID)
        {
            perms[6] = (perms[6] == 'x') ? 's' : 'S';
        }
        if (mode & S_ISVTX)
        {
            perms[9] = (perms[9] == 'x') ? 't' : 'T';
        }
        
        //格式化信息
        char buf[1024] = {0};
        int off = 0;
        off += sprintf(buf, "%s ", perms);//连接权限位
        off += sprintf(buf + off, " %3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);//连接连接数、uid、gid
        off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);//连接文件大小，以8位的长度展现
			
		
		//const char * format = "%b %e %H:%M"; //时间格式
		const char * format = "%b %e %H:%M";
		struct timeval tv;
		gettimeofday(&tv, NULL);
		time_t local_time = tv.tv_sec;
		
		if(sbuf.st_mtime > local_time 
			|| (local_time -  sbuf.st_mtime) > 60*60*180)
			format = "%b %e %Y"; 			
		
		
		char datebuf[64] = {0};
		struct tm * p_tm = localtime(&sbuf.st_mtime);
	
		strftime(datebuf, sizeof(datebuf), format, p_tm);
		
		
		off += sprintf(buf + off, "%s ",datebuf);
		
	    if (S_ISLNK(sbuf.st_mode))
		{
			char tmp[1024] = {0};
			readlink(dt->d_name, tmp, sizeof(tmp));
			off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
		} else
		{
			off += sprintf(buf + off, "%s\r\n", dt->d_name);
		}
		printf("%s", buf);	
	
		
    }

    return 1;
}

static void do_syst(session_t *sess)
{
    ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

static void do_feat(session_t *sess)
{
    ftp_lreply(sess, FTP_FEAT, "Features:");
    writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
    writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV\r\n"));
    writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
    writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
    writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
    writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
    writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
    writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
    ftp_reply(sess, FTP_FEAT, "End");
}
static void do_cwd(session_t *sess)
{
    if (chdir(sess->arg) >= 0)
    {
        ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
        return;
    }
    ftp_reply(sess, FTP_FILEFAIL, "Fail to change directory");
}


static void do_cdup(session_t *sess)
{
    if (chdir("..") >= 0)
    {
        ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
        return;
    }
    ftp_reply(sess, FTP_FILEFAIL, "Fail to change directory");
}


static void do_quit(session_t *sess)
{
    ftp_reply(sess, FTP_GOODBYE, "Good bye");
    exit(EXIT_SUCCESS);
}

static void do_rest(session_t *sess)
{
    //atoll;
    sess->restart_pos = str_to_longlong(sess->arg);
    char text[1024] = {0};
    sprintf(text, "Restart position accpted (%lld)", sess->restart_pos);
    ftp_reply(sess, FTP_RESTOK, text);
}

static void do_abor(session_t *sess)
{
    ftp_reply(sess, FTP_ABOR_NOCONN, "NO transfer to ABOR.");
}

static void do_pwd(session_t *sess)
{
    char dir[1024] = {0};
    char buf[1024] = {0};
    //list_common(sess, 0);
	list_common();
    getcwd(dir, 1024);
    sprintf(buf, "\"%s\"", dir);
    ftp_reply(sess, FTP_PWDOK, buf);
}

static void do_type(session_t *sess)
{
    if (strcmp(sess->arg, "A") == 0)
    {
        ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
    }
    else if (strcmp(sess->arg, "I") == 0)
    {
        ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
    }
    else
    {
        ftp_reply(sess, FTP_BADCMD, "Unrecognised Type cmd.");
    }
}

static void do_noop(session_t *sess)
{
    ftp_reply(sess, FTP_NOOPOK, "NOOP ok");
}

static void do_help(session_t *sess)
{
    ftp_lreply(sess, FTP_HELP, "The following commands are recognized");
    writen(sess->ctrl_fd, "ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n", strlen("ABOR ACCT ALLO APPE CDUP CWD  DELE EPRT EPSV FEAT HELP LIST MDTM MKD\r\n"));
    writen(sess->ctrl_fd, "MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n", strlen("MODE NLST NOOP OPTS PASS PASV PORT PWD  QUIT REIN REST RETR RMD  RNFR\r\n"));
    writen(sess->ctrl_fd, "RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n", strlen("RNTO SITE SIZE SMNT STAT STOR STOU STRU SYST TYPE USER XCUP XCWD XMKD\r\n"));
    writen(sess->ctrl_fd, "XPWD XRMD\r\n", strlen("XPWD XRMD\r\n"));
    ftp_reply(sess, FTP_HELP,"HELP OK");
}


static void do_site_chmod(session_t *sess, char *chmod_arg)
{
    if (strlen(chmod_arg) == 0)
    {
        ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
        return;
    }
    char perm[100] = {0};
    char file[100] = {0};
    str_split(chmod_arg , perm, file, ' ');
    if (strlen(file) == 0)
    {
        ftp_reply(sess, FTP_BADCMD, "SITE CHMOD needs 2 arguments.");
        return;
    }

    unsigned int mode = str_octal_to_uint(perm);
    if (chmod(file, mode) < 0)
    {
        ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD command failed.");
    }
    else
    {
        ftp_reply(sess, FTP_CHMODOK, "SITE CHMOD command ok.");
    }
}
static void do_site_umask(session_t *sess, char *umask_arg)
{
    if (strlen(umask_arg) == 0)
    {
        char text[1024] = {0};
        sprintf(text, "Your current UMASK is 0%o", tunable_local_umask);
        ftp_reply(sess, FTP_UMASKOK, text);
    }
    else
    {
        unsigned int um = str_octal_to_uint(umask_arg);
        umask(um);
        char text[1024] = {0};
        sprintf(text, "UMASK set to 0%o", um);
        ftp_reply(sess, FTP_UMASKOK, text);
    }
}
