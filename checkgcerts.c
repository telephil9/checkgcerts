#include <u.h>
#include <libc.h>
#include <draw.h>
#include <event.h>
#include <keyboard.h>
#include "a.h"

Server servers[] = {
	{ "IMAP", Simap, "net!imap.gmail.com!imaps", "/sys/lib/tls/mail", 0 },
	{ "SMTP", Ssmtp, "net!smtp.gmail.com!587", "/sys/lib/tls/smtp", 0 },
};

enum
{
	Padding = 10,
};

char* menustr[] = { "refresh", "quit", 0 };
Menu menu = { menustr };

Image *bg;
Image *errfg;

void
redraw(void)
{
	int i, n, w, h, x, y;
	Point p;
	Rectangle r;
	Image *c;
	Tm *t;
	char *s;

	t = localtime(time(0));
	s = smprint("%02d:%02d", t->hour, t->min);
	n = nelem(servers);
	w = Dx(screen->r)-2*Padding;
	h = (Dy(screen->r)-font->height-2-(n+1)*Padding)/n;
	p = addpt(screen->r.min, Pt(2, 2));
	draw(screen, screen->r, bg, nil, ZP);
	string(screen, p, display->black, ZP, font, s);
	free(s);
	p.x += Padding-2;
	p.y += font->height + Padding;
	for(i = 0; i < n; i++){
		r = Rect(p.x, p.y, p.x+w, p.y+h);
		c = servers[i].status ? errfg : display->black;
		border(screen, r, 1, c, ZP);
		x = (Dx(r)-stringwidth(font, servers[i].name))/2;
		y = (Dy(r)-font->height)/2;
		string(screen, addpt(p, Pt(x, y)), c, ZP, font, servers[i].name);
		p.y += h + Padding;
	}	
}

void
eresized(int new)
{
	if(new && getwindow(display, Refnone)<0)
		sysfatal("cannot reattach: %r");
	redraw();
}

void
checkcerts(void)
{
	int ok, i;

	ok = -1;
	for(i = 0; i < nelem(servers); i++){
		switch(servers[i].type){
		case Simap:
			ok = imapcheck(servers[i].addr, servers[i].thumbfile);
			break;
		case Ssmtp:
			ok = smtpcheck(servers[i].addr, servers[i].thumbfile);
			break;
		}
		servers[i].status=ok;
	}
	redraw();
}

void
main(void)
{
	Event e;
	int n, timer;

	if(initdraw(nil, nil, "certcheck")<0)
		sysfatal("initdraw: %r");
	bg = allocimagemix(display, DPalebluegreen, DWhite);
	errfg = allocimage(display, Rect(0,0,1,1), screen->chan, 1, DRed);
	einit(Emouse|Ekeyboard);
	timer = etimer(0, 5*60*1000);
	eresized(0);
	for(;;){
		n = event(&e);
		switch(n){
		default:
			if(n==timer)
				checkcerts();
			break;
		case Ekeyboard:
			if(e.kbdc=='q' || e.kbdc==Kdel)
				exits(nil);
			break;
		case Emouse:
			if(e.mouse.buttons&4){
				n = emenuhit(3, &e.mouse, &menu);
				if(n==0)
					checkcerts();
				else if(n == 1)
					exits(nil);
			} 
			break;
		}
	}
}
