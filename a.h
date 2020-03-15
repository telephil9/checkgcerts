typedef struct Server Server;

struct Server
{
	char *name;
	int  type;
	char *addr;
	char *thumbfile;
	int  status;
};

enum
{
	Simap,
	Ssmtp,
};

int smtpcheck(char *addr, char *thumbfile);
int imapcheck(char *addr, char *thumbfile);
