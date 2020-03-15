#include <u.h>
#include <libc.h>
#include <libsec.h>
#include <bio.h>

int
checkcert(int ofd, char *addr, char *thumbfile)
{
	Thumbprint *thumb;
	TLSconn *conn;
	int r, fd;
	char *s;

	r = 0;
	conn = mallocz(sizeof *conn, 1);
	fd = tlsClient(ofd, conn);
	if(fd<0){
		fprint(2, "%s: could not open tls client: %r\n", addr);
		close(ofd);
		return -1;
	}
	s = smprint("%s.exclude", thumbfile);
	thumb = initThumbprints(thumbfile, s, "x509");
	free(s);
	if(thumb!=nil){
		if(!okCertificate(conn->cert, conn->certlen, thumb)){
			fprint(2, "%s: invalid certificate: %r\n", addr);
			r = -1;
		}
		freeThumbprints(thumb);
	}
	free(conn->cert);
	free(conn->sessionID);
	close(fd);
	return r;
}

void
smtpsend(Biobuf *bout, char *fmt, ...)
{
	va_list arg;

	va_start(arg, fmt);
	Bvprint(bout, fmt, arg);
	Bflush(bout);
	va_end(arg);
}

char*
readline(Biobuf *bin)
{
	char buf[1024]; //XXX: should be big enough
	int i, c;

	i = 0;
	for(;;){
		c = Bgetc(bin);
		switch(c){
		case -1:
			return strdup("500 connection closed");
		case '\r':
			c = Bgetc(bin);
			if(c=='\n'){
		case '\n':
				buf[i] = '\0';
				return strdup(buf);
			}
			Bungetc(bin);
			buf[i++] = '\r';
			break;
		default:
			buf[i++] = c;
			break;
		}
	}
}

char*
smtpresp(Biobuf *bin)
{
	char c, *s, *e;
	int n;

	for(;;){
		s = readline(bin);
		n = atoi(s);
		if(n/100 != 2){
			e = strdup(s+4);
			free(s);
			return e;
		}
		c = s[3];
		free(s);
		if(c==' ')
			break;
	}
	return nil;
}

int
smtpcheckresp(Biobuf *bin, Biobuf *bout, char *cmd)
{
	char *err;

	err = smtpresp(bin);
	if(err!=nil){
		fprint(2, "smtp %s error: %s\n", cmd, err);
		free(err);
		Bterm(bin);
		Bterm(bout);
		return -1;
	}
	return 0;
}

int
smtpcheck(char *addr, char *thumbfile)
{
	int fd, ofd, rc;
	Biobuf *bin, *bout;

	fd = dial(addr, 0, 0, 0);
	if(fd<0){
		fprint(2, "could not connect to '%s': %r\n", addr);
		return -1;
	}
	ofd = dup(fd, -1);
	bin = Bfdopen(fd, OREAD);
	bout = Bfdopen(ofd, OWRITE);
	rc = smtpcheckresp(bin, bout, "CONNECT");
	if(rc<0)
		return rc;
	smtpsend(bout, "EHLO %s\r\n", sysname());
	rc = smtpcheckresp(bin, bout, "EHLO");
	if(rc<0)
		return rc;
	smtpsend(bout, "STARTTLS\r\n");
	rc = smtpcheckresp(bin, bout, "STARTTLS");
	if(rc<0)
		return rc;
	rc = checkcert(fd, addr, thumbfile);
	Bterm(bin);
	Bterm(bout);
	return rc;
}

int
imapcheck(char *addr, char *thumbfile)
{
	int fd, rc;

	fd = dial(addr, 0, 0, 0);
	if(fd<0){
		fprint(2, "could not connect to '%s': %r", addr);
		return -1;
	}
	rc = checkcert(fd, addr, thumbfile);
	close(fd);
	return rc;
}
