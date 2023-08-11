#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include <stdio.h>

#include <unistd.h>
#include <sys/wait.h>

int unmount(const char* path, int flags);
int printf(const char* fmt, ...);

int run_and_wait(const char* path, const char** argv) {
    int pid = fork();
    if (!pid) {
        char* envp[] = {NULL};
        if (execve(path, argv, envp) == -1) {
            printf("Failed to execve\n");
            return -1;
        }
    }
    int status = 0;
    waitpid(pid, &status, 0);
    return status;
}

void spin_until_file_appears(const char* path) {
    printf("Spinning until path appears: %s\n", path);
    const char* remote_path_start = "root@localhost:";

    while (true) {
        if (access(path, F_OK) == 0) {
            printf("File appeared! %s\n", path);
            return;
        }
        else {
            int delay_seconds = 5;
            printf("File hasn't appeared yet, will wait %d seconds...\n", delay_seconds);
            sleep(delay_seconds);
        }
    }
}

int main(int argc, const char** argv) {
    printf("*** asr_wrapper invoked ***\n");
    printf("\targc: %d\n", argc);
    for (int i = 0; i < argc; i++) {
        printf("\targv[%d] = %s\n", i, argv[i]);
    }

    /*
    printf("Unmounting /mnt1...\n");
    const char* umount_path = "/usr/bin/umount";
    const char* umount_argv[] = {umount_path, "/mnt1", NULL};
    int ret = run_and_wait(umount_path, umount_argv);
    if (ret != 0) {
        printf("Unmounting the System partition failed\n");
        return -1;
    }
    */
    printf("Mounting /mnt2...\n");
    const char* mount_path = "/sbin/mount_hfs";
    const char* mount_argv[] = {mount_path, "/dev/disk0s2s1", "/mnt2", NULL};
    int ret = run_and_wait(mount_path, mount_argv);
    if (ret != 0) {
        printf("Mounting /dev/disk0s2s1 to /mnt2 failed\n");
        return -1;
    }

    // Inform the host by creating a sentinel file
    // touch /mnt2/sentinel__device_is_ready_for_host_to_send_rootfs
    printf("Creating sentinel file to ask the host to send the root filesystem...\n");
    fopen("/mnt2/sentinel__device_is_ready_for_host_to_send_rootfs" ,"a");

    spin_until_file_appears("/mnt2/sentinel__rootfs_is_fully_uploaded");

    printf("Root filesystem is uploaded!\n");
    const char* asr_path = "/usr/sbin/asr";
    const char* asr_argv[] = {asr_path, "-source", "/mnt2/root_filesystem.dmg", "-target", "/dev/disk0s1", "-erase", "-noprompt", NULL};
    ret = run_and_wait(asr_path, asr_argv);
    printf("asr ret = %d\n", ret);

    sleep(20);

    for (int i = 0; i < 3; i++) {
        printf("Unmounting /mnt2 to match what restored_external expects...\n");
        const char* umount_path = "/usr/bin/umount";
        const char* umount_argv[] = {umount_path, "/mnt2", NULL};
        ret = run_and_wait(umount_path, umount_argv);
        if (ret != 0) {
            printf("Unmounting the Data partition failed. Sleeping...\n");
            sleep(10);
            //return -1;
        }
        else {
            break;
        }
    }

    /*
    printf("Mounting /dev/disk0s2s1 to /mnt2...\n");
    const char* mount_hfs_path = "/sbin/mount_hfs";
    const char* mount_hfs_argv[] = {mount_hfs_path, "/dev/disk0s2s1", "/mnt2", NULL};
    int ret = run_and_wait(mount_hfs_path, mount_hfs_argv);
    if (ret != 0) {
        printf("Mounting the Data partition failed\n");
        return -1;
    }
    printf("Mounting the Data partition succeeded\n");
    */

    // spin while waiting for /mnt2/sentinel__rootfs_is_fully_uploaded

    return 0;
}
