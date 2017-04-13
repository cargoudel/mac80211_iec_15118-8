/* Copyright (c) 2017 Intel Deutschland GmbH
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <linux/bpf.h>
#include "bpf_load.h"

int main(int argc, char **argv)
{
	char filename[256];
	char fdstr[100];
	char *args[] = {
		"iw",
		"dev",
		argv[1],
		"set",
		"filter",
		fdstr,
		NULL,
	};

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);

	if (argc != 2) {
		printf("usage: %s <ifname>\n", argv[0]);
		return 1;
	}

	if (load_bpf_file(filename)) {
		printf("%s", bpf_log_buf);
		return 1;
	}

	if (!prog_cnt) {
		printf("load_bpf_file: nothing loaded\n");
		return 1;
	}

	snprintf(fdstr, sizeof(fdstr), "%d", prog_fd[0]);

	if (fcntl(prog_fd[0], F_SETFD, 0) < 0) {
		printf("fcntl error: %d: %s\n", errno, strerror(errno));
		return 1;
	}

	return execve("/root/iw", args, NULL);
}
