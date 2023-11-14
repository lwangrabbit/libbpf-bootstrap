// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include "uprobe_attach.skel.h"
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <sys/resource.h>
#include <unistd.h>

static int	libbpf_print_fn(enum libbpf_print_level level, const char *format,
		va_list args)
{
	return (vfprintf(stderr, format, args));
}

int	main(int argc, char **argv)
{
	struct hello_bpf *skel;
	int err, i;
	LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts);

	if (2 != argc)
	{
		fprintf(stderr, "usage: %s attch pid\n", argv[0]);
		return (-1);
	}

	int attach_pid;
	char binary_path[256] = {};
	attach_pid = atoi(argv[1]);
	sprintf(binary_path, "/proc/%d/exe", attach_pid);

	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = hello_bpf__open_and_load();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return (1);
	}

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "uprobed_add";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
		* to. libbpf will automatically find the offset for us if we provide the
		* function name. If the function name is not specified, libbpf will try
		* to use the function offset instead.
		*/
	skel->links.uprobe_add = bpf_program__attach_uprobe_opts(skel->progs.uprobe_add,
			attach_pid /* self pid */, binary_path, 0 /* offset for function */,
			&uprobe_opts /* opts */);
	if (!skel->links.uprobe_add)
	{
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
		* processes that use the same binary executable; to do that we need
		* to specify -1 as PID, as we do here
		*/
	uprobe_opts.func_name = "uprobed_add";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_add = bpf_program__attach_uprobe_opts(skel->progs.uretprobe_add,
			attach_pid /* self pid */, binary_path, 0 /* offset for function */,
			&uprobe_opts /* opts */);
	if (!skel->links.uretprobe_add)
	{
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Attach tracepoint handler */
	uprobe_opts.func_name = "uprobed_sub";
	uprobe_opts.retprobe = false;
	/* uprobe/uretprobe expects relative offset of the function to attach
		* to. libbpf will automatically find the offset for us if we provide the
		* function name. If the function name is not specified, libbpf will try
		* to use the function offset instead.
		*/
	skel->links.uprobe_sub = bpf_program__attach_uprobe_opts(skel->progs.uprobe_sub,
			attach_pid /* self pid */, binary_path, 0 /* offset for function */,
			&uprobe_opts /* opts */);
	if (!skel->links.uprobe_sub)
	{
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* we can also attach uprobe/uretprobe to any existing or future
		* processes that use the same binary executable; to do that we need
		* to specify -1 as PID, as we do here
		*/
	uprobe_opts.func_name = "uprobed_sub";
	uprobe_opts.retprobe = true;
	skel->links.uretprobe_sub = bpf_program__attach_uprobe_opts(skel->progs.uretprobe_sub,
			attach_pid /* self pid */, binary_path, 0 /* offset for function */,
			&uprobe_opts /* opts */);
	if (!skel->links.uretprobe_sub)
	{
		err = -errno;
		fprintf(stderr, "Failed to attach uprobe: %d\n", err);
		goto cleanup;
	}

	/* Let libbpf perform auto-attach for uprobe_sub/uretprobe_sub
		* NOTICE: we provide path and symbol info in SEC for BPF programs
		*/
	err = hello_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
		goto cleanup;
	}

	printf("Successfully started! Please run `sudo cat
			/ sys / kernel / debug / tracing /
			trace_pipe` "
						"to see output of the BPF programs.\n");

	for (i = 0;; i++)
	{
		fprintf(stderr, ".");
		sleep(1);
	}

cleanup:
	hello_bpf__destroy(skel);
	return (-err);
}