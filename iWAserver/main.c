//
//  main.c
//  iWAserver
//
//  Created by louhao on 13-1-25.
//  Copyright (c) 2013年 louhao. All rights reserved.
//

/*
 This exmple program provides a trivial server program that listens for TCP
 connections on port 9995.  When they arrive, it writes a short message to
 each client connection, and closes each connection once it is flushed.
 
 Where possible, it exits cleanly in response to a SIGINT (ctrl-c).
 */


#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#ifndef WIN32
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#include <sys/socket.h>
#endif

#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/event.h>

#include <my_global.h>
#include <mysql.h>

#include "iwaserver.pb-c.h"


void iWA_AuthServer_BuffereventReadCb(struct bufferevent *bev);
void iWA_AuthServer_HandlePacketQueue(void);



#define LISTEN_PORT 3724
#define LISTEN_BACKLOG 32

struct event *timer_event;
struct timeval tv;


void do_accept(evutil_socket_t listener, short event, void *arg);
void read_cb(struct bufferevent *bev, void *arg);
void error_cb(struct bufferevent *bev, short event, void *arg);
void write_cb(struct bufferevent *bev, void *arg);
void time_cb(int fd, short _event, void *argc);





int main(int argc, char *argv[])
{
    int ret;
    evutil_socket_t listener;
    struct sockaddr_in sin;
    struct event_base *base;
    struct event *listen_event;
    
#ifdef WIN32
	WSADATA wsa_data;
	WSAStartup(0x0201, &wsa_data);
#endif

    if(!iWA_AuthServer_Init())   return 0;
    
    
    listener = socket(AF_INET, SOCK_STREAM, 0);
    assert(listener > 0);
    evutil_make_listen_socket_reuseable(listener);
    
    
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = 0;
    sin.sin_port = htons(LISTEN_PORT);
    
    if (bind(listener, (struct sockaddr *)&sin, sizeof(sin)) < 0) {
        perror("bind");
        return 1;
    }
    
    if (listen(listener, LISTEN_BACKLOG) < 0) {
        perror("listen");
        return 1;
    }
    
    printf ("Listening...\n");
    
    evutil_make_socket_nonblocking(listener);
    
    base = event_base_new();
    assert(base != NULL);
    
    listen_event = event_new(base, listener, EV_READ|EV_PERSIST, do_accept, (void*)base);
    event_add(listen_event, NULL);


    tv.tv_sec=5; 
    tv.tv_usec=0;
    timer_event = event_new(base, -1, 0, time_cb, NULL);
    //evtimer_set(&timer_event, time_cb, NULL);
    event_add(timer_event, &tv);

    
    event_base_dispatch(base);
    
    printf("The End.");
    return 0;
}

void do_accept(evutil_socket_t listener, short event, void *arg)
{
    struct event_base *base = (struct event_base *)arg;
    evutil_socket_t fd;
    struct sockaddr_in sin;
    int slen;
    struct bufferevent *bev;
    
    fd = accept(listener, (struct sockaddr *)&sin, &slen);
    if (fd < 0) {
        perror("accept");
        return;
    }
    if (fd > FD_SETSIZE) {
        perror("fd > FD_SETSIZE\n");
        return;
    }
    
    printf("ACCEPT: fd = %u\n", fd);
    
    bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
    bufferevent_setcb(bev, read_cb, NULL, error_cb, arg);
    bufferevent_enable(bev, EV_READ|EV_WRITE|EV_PERSIST);

    iWA_AuthSession_SessionNew(bev);
}


void read_cb(struct bufferevent *bev, void *arg)
{

#if 0

#define MAX_LINE    256
    char line[MAX_LINE+1];
    int n;
    evutil_socket_t fd = bufferevent_getfd(bev);


    
    IWAserverAuth__LogRegClient *log;
    
    while (n = bufferevent_read(bev, line, MAX_LINE), n > 0) 
    {
        
            line[n] = '\0';
            //printf("fd=%u, read line: %s\n", fd, line);
            
            //bufferevent_write(bev, line, n);
            
            log = i_waserver_auth__log_reg_client__unpack(NULL, n-4, line+4);
    }
#endif

    iWA_AuthServer_BuffereventReadCb(bev);

#if 0
#define IWA_PACKET_HEADER_SIZE    (4)
    unsigned char header[IWA_PACKET_HEADER_SIZE];
    struct evbuffer *evb;
    int evb_len;
    unsigned short packet_len, packet_type;
    iwaserver_packet *packet;

    evb = bufferevent_get_input(bev);
    if(evb == NULL)     return;

    evb_len = evbuffer_get_length(evb);
    if(evb_len < IWA_PACKET_HEADER_SIZE)    return;

    if(evbuffer_copyout(evb, header, IWA_PACKET_HEADER_SIZE) < IWA_PACKET_HEADER_SIZE)  return;

    packet_len = (unsigned short)header[0] |((unsigned short)header[1] << 8);
    packet_type = (unsigned short)header[2] |((unsigned short)header[3] << 8);

    if(evb_len < packet_len + 4)    return;

    packet = (iwaserver_packet*)malloc(packet_len <= 4 ? sizeof(iwaserver_packet) : sizeof(iwaserver_packet) + packet_len - 4);
    if(packet == NULL)  return;

    packet->next = NULL;
    packet->session = 0;
    packet->len = packet_len;
    packet->type = packet_type;

    if(evbuffer_drain(evb, IWA_PACKET_HEADER_SIZE) < 0)     return;
    if(evbuffer_remove(evb, packet->data, packet_len) != packet_len)    return;

    packet->next = (void*)packet_queue;
    packet_queue = packet;

#endif    
}

void write_cb(struct bufferevent *bev, void *arg) {}

void error_cb(struct bufferevent *bev, short event, void *arg)
{
    evutil_socket_t fd = bufferevent_getfd(bev);
    printf("fd = %u, ", fd);
    if (event & BEV_EVENT_TIMEOUT) {
        printf("Timed out\n"); //if bufferevent_set_timeouts() called
    }
    else if (event & BEV_EVENT_EOF) {
        printf("connection closed\n");
    }
    else if (event & BEV_EVENT_ERROR) {
        printf("some other error\n");
    }
    bufferevent_free(bev);

    iWA_AuthSession_SessionEnd(bev);
}



void time_cb(int fd,short _event,void *argc)
{
    printf("timer wakeup");
    event_add(timer_event, &tv);

    iWA_AuthServer_HandlePacketQueue();
}














#if 0


static const char MESSAGE[] = "Hello, World!\n";

static const int PORT = 9995;

static void listener_cb(struct evconnlistener *, evutil_socket_t,
                        struct sockaddr *, int socklen, void *);
static void conn_writecb(struct bufferevent *, void *);
static void conn_eventcb(struct bufferevent *, short, void *);
static void signal_cb(evutil_socket_t, short, void *);

int
main(int argc, char **argv)
{
	struct event_base *base;
	struct evconnlistener *listener;
	struct event *signal_event;
          
	struct sockaddr_in sin;
#ifdef WIN32
	WSADATA wsa_data;
	WSAStartup(0x0201, &wsa_data);
#endif
    
    MYSQL *conn;
    
    Foo__Person__PhoneNumber phones[3];
    Foo__Person__PhoneNumber* ph[3];
    Foo__Person person;
    Foo__LookupResult foo, *f2;
    char buf[1024];
    int msg_len;
    
    foo__person__phone_number__init(&phones[0]);
    phones[0].number = "10086";
    phones[0].has_type = 1;
    phones[0].type = FOO__PERSON__PHONE_TYPE__HOME;
    
    foo__person__phone_number__init(&phones[1]);
    phones[1].number = "13631629707";
    phones[1].has_type = 0;
    phones[1].type = FOO__PERSON__PHONE_TYPE__WORK;
    
    foo__person__phone_number__init(&phones[2]);
    phones[2].number = "13143433744";
    phones[2].has_type = 1;
    phones[2].type = FOO__PERSON__PHONE_TYPE__MOBILE;
    
    ph[0] = &phones[0];
    ph[1] = &phones[1];
    ph[2] = &phones[2];
    
    foo__person__init(&person);
    person.name = "bob";
    person.id = 7;
    person.email = "bob@test.com";
    person.n_phone = 3;
    person.phone = ph;
    
    foo__lookup_result__init(&foo);
    foo.person = &person;
    
    msg_len = foo__lookup_result__pack(&foo, buf);
    f2 = foo__lookup_result__unpack(NULL, msg_len, buf);
    
    
    
    printf("MySQL client version: %s\n", mysql_get_client_info());

    conn = mysql_init(NULL);
    if (conn == NULL) {
        printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        exit(1);
    }
    if (mysql_real_connect(conn, "localhost", "root",
                           "", NULL, 0, NULL, 0) == NULL) {
        printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        exit(1);
    }
    if (mysql_query(conn, "create database testdb")) {
        printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        exit(1);
    }  
    mysql_close(conn);
    
    
    
	base = event_base_new();
	if (!base) {
		fprintf(stderr, "Could not initialize libevent!\n");
		return 1;
	}
    
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(PORT);
    
	listener = evconnlistener_new_bind(base, listener_cb, (void *)base,
                                       LEV_OPT_REUSEABLE|LEV_OPT_CLOSE_ON_FREE, -1,
                                       (struct sockaddr*)&sin,
                                       sizeof(sin));
    
	if (!listener) {
		fprintf(stderr, "Could not create a listener!\n");
		return 1;
	}
    
	signal_event = evsignal_new(base, SIGINT, signal_cb, (void *)base);
    
	if (!signal_event || event_add(signal_event, NULL)<0) {
		fprintf(stderr, "Could not create/add a signal event!\n");
		return 1;
	}
    
	event_base_dispatch(base);
    
	evconnlistener_free(listener);
	event_free(signal_event);
	event_base_free(base);
    
	printf("done\n");
	return 0;
}

static void
listener_cb(struct evconnlistener *listener, evutil_socket_t fd,
            struct sockaddr *sa, int socklen, void *user_data)
{
	struct event_base *base = user_data;
	struct bufferevent *bev;
    
	bev = bufferevent_socket_new(base, fd, BEV_OPT_CLOSE_ON_FREE);
	if (!bev) {
		fprintf(stderr, "Error constructing bufferevent!");
		event_base_loopbreak(base);
		return;
	}
	bufferevent_setcb(bev, NULL, conn_writecb, conn_eventcb, NULL);
	bufferevent_enable(bev, EV_WRITE);
	bufferevent_disable(bev, EV_READ);
    
	bufferevent_write(bev, MESSAGE, strlen(MESSAGE));
}

static void
conn_writecb(struct bufferevent *bev, void *user_data)
{
	struct evbuffer *output = bufferevent_get_output(bev);
	if (evbuffer_get_length(output) == 0) {
		printf("flushed answer\n");
		bufferevent_free(bev);
	}
}

static void
conn_eventcb(struct bufferevent *bev, short events, void *user_data)
{
	if (events & BEV_EVENT_EOF) {
		printf("Connection closed.\n");
	} else if (events & BEV_EVENT_ERROR) {
		printf("Got an error on the connection: %s\n",
               strerror(errno));/*XXX win32*/
	}
	/* None of the other events can happen here, since we haven't enabled
	 * timeouts */
	bufferevent_free(bev);
}

static void
signal_cb(evutil_socket_t sig, short events, void *user_data)
{
	struct event_base *base = user_data;
	struct timeval delay = { 2, 0 };
    
	printf("Caught an interrupt signal; exiting cleanly in two seconds.\n");
    
	event_base_loopexit(base, &delay);
}

#endif


#if 0

#include <stdio.h>

int main(int argc, const char * argv[])
{

    // insert code here...
    printf("Hello, World!\n");
    return 0;
}

#endif
