#pragma once
#include <sys/wait.h>
#include <signal.h>

bool is_dir_exist(const char *s);

int bind_mount_(const char *from, const char *to);
int tmpfs_mount(const char *from, const char *to);
char *random_strc(int n = 8);
int get_random(int from=0, int to=9999);

