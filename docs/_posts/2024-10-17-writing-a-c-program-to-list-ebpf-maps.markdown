---
layout: post
title:  "Writing a C Program to List eBPF Maps"
date:   2024-10-17 12:37:01 +0200
categories: ebpf programming
---

To list eBPF maps and display their basic info you can use the `bpf()` system call.

The `bpf()` syscall doesn't just do one thing but it is used to perform different
commands on an eBPF map or program. Its signature is as follows:

{% highlight c %}
int bpf(int cmd, union bpf_attr *attr, unsigned int size);
{% endhighlight %}

The first argument to `bpf()`, `cmd`, specifies which command to perform on an
eBPF map or program.

There is no single command to list eBPF maps, but you rather execute a group of
`BPF_MAP_GET_NEXT_ID`, `BPF_MAP_GET_FD_BY_ID`, and `BPF_OBJ_GET_INFO_BY_FD`
commands in a loop. If there are no more eBPF maps left to iterate,
`BPF_MAP_GET_NEXT_ID`command returns a value `ENOENT`.

In the following C program I iterate through eBPF maps and print their details.
Instead of invoking the `bpf()` syscall directly, I'm using convenient wrapper
functions provided by *libbpf*. Notice the usage of the
`libbpf_bpf_map_type_str()` to decode type of eBPF map as string from its
integer representation.

{% highlight c %}
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
  struct bpf_map_info info = {};
  __u32 info_len = sizeof(info);
  __u32 id = 0;
  int err = 0;
  int fd = 0;

  while (true) {
    // Get the ID of the next map after the value specified in id.
    err = bpf_map_get_next_id(id, &id);
    if (err) {
      if (errno == EPERM) {
        perror("bpf_map_get_next_id");
        exit(EXIT_FAILURE);
      }
      if (errno == ENOENT)
        break;

      perror("bpf_map_get_next_id");
      break;
    }

    // Get the file descriptor for the specified map ID.
    fd = bpf_map_get_fd_by_id(id);
    if (fd < 0) {
      if (errno == EPERM) {
        perror("bpf_map_get_fd_by_id");
        exit(EXIT_FAILURE);
      }
      if (errno == ENOENT)
        continue;

      perror("bpf_map_get_fd_by_id");
      break;
    }

    // Retrieves information about the object (map) referred to by the file
    // descriptor.
    err = bpf_obj_get_info_by_fd(fd, &info, &info_len);
    if (err) {
      perror("bpf_obj_get_info_by_fd");
      close(fd);
      break;
    }

    const char *map_type_str;
    map_type_str = libbpf_bpf_map_type_str(info.type);

    printf("%d: ", id);
    if (map_type_str)
      printf("%s  ", map_type_str);
    else
      printf("type %u  ", info.type);

    printf("name: %s  ", info.name);
    printf("flags 0x%x\n", info.map_flags);
  }

  exit(EXIT_SUCCESS);
}
{% endhighlight %}

The `bpf_map_get_next_id()` gets the ID of the next map after the specified ID.
The `bpf_map_get_fd_by_id()` returns the file descriptor for the specified map
ID. Finally, the `bpf_obj_get_info_by_fd()` retrieves information about the eBPF
map referred to by the file descriptor.

You can compile this program with the following command:

```
clang main.c -lbpf -o list-ebpf-maps
```

```
$ sudo ./list-ebpf-maps
11: hash_of_maps  name: cgroup_hash  flags 0x0
```

How to run this program without sudo?
How to add capabilities to executable binary?
Another blog with Hello world system programming in C to explain error handling?
