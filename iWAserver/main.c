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






int main(int argc, char *argv[])
{

    return iWA_AuthServer_Main();

}















