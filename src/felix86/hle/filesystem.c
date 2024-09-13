#include "felix86/hle/filesystem.h"
#include "felix86/common/log.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>

char sandbox_path[PATH_MAX] = {0};
bool mounted = false;

void felix86_fs_init(const char* squashfs_path)
{
    snprintf(sandbox_path, sizeof(sandbox_path), "/tmp/felix86-%d-XXXXXX", getpid());
    mkdtemp(sandbox_path);

    pid_t pid = fork();

    if (pid == 0) {
        const char* args[4] = {
            "squashfuse",
            squashfs_path,
            sandbox_path,
            NULL,
        };

        execvp("squashfuse", (char* const*)args);
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            ERROR("Failed to mount squashfs image");
        }

        VERBOSE("Mounted squashfs image at %s", sandbox_path);
        mounted = true;
    }
}

void felix86_fs_cleanup()
{
    if (!mounted) {
        return;
    }

    pid_t pid = fork();

    if (pid == 0) {
        char* args[4] = {
            "fusermount",
            "-u",
            "-q",
            sandbox_path,
            NULL,
        };

        execvp("fusermount", args);
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            ERROR("Failed to unmount squashfs image, please unmount manually: %s", sandbox_path);
        }

        VERBOSE("Unmounted squashfs image at %s", sandbox_path);
        rmdir(sandbox_path);
    }
}

u32 felix86_fs_readlinkat(u32 dirfd, const char* pathname, char* buf, u32 bufsiz)
{
    char path[PATH_MAX] = {0};
    bool is_absolute = felix86_make_path_safe(path, sizeof(path), pathname);

    if (is_absolute) {
        return readlink(path, buf, bufsiz);
    } else {
        ERROR("Unimplemented readlinkat with a relative path");
    }
}