#ifndef UTILS_H
#define UTILS_H

int xopenpath(const char *path);
int xdup(int fd);
int xclose(int fd);
int xfdpath(int fd, char *path);

#endif /* UTILS_H */
