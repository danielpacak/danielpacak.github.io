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
