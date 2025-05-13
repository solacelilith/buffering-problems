// Compiled with "gcc buffering-problems.c -g -o buffering-problems"
// Simple and secure application to transfer data between a control tower and a plane's various devices.
// Communication from a terminal with human input is not supported. A custom script is necessary.

#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>

#define PKT_OPT_PING 0x0
#define PKT_OPT_CREATE_DEVICE 0x1
#define PKT_OPT_OPEN_DEVICE 0x2
#define PKT_OPT_DEVICE_SECRET 0x3
#define PKT_OPT_DEVICE_DATA 0x4
#define PKT_OPT_CHOOSE_OPEN 0x5
#define PKT_OPT_DEVICE_UPDATE 0x6
#define PKT_OPT_CLOSE_CONNECTION 0x10

struct {
    int fd;
    int index;
    char id[33];
    // AUTHOR'S NOTE: 1st vuln - able to leak the secret, because the null-byte isn't added if the ID buffer is filled
    char secret[33];
    bool unlocked;
    char data[53];
} typedef device_t;

ssize_t read_line(int fd, char *buf, size_t size) {
    if (size == 0) {
        return -1;
    }

    size_t count = 0;
    while (count < size) {
        ssize_t res = read(fd, buf + count, 1);
        if (res <= 0) {
            if (res == 0) {
                break;
            }
            return -1;
        }
        if (buf[count] == '\n') {
            break;
        }
        count++;
    }
    buf[count] = '\0';
    return count;
}

// Testing the connection
void ping() {
    printf("[PONG_OK]\n");
    return;
}

// Creating a new device
void create_device(int devices_fd) {
    int fd;
    char id[66];
    char secret[66];
    char data[66];

    printf("[ID_IN_START]\n");
    if (fgets(id, 34, stdin) != NULL) {
        printf("[ID_IN_END]\n");
        printf("[ID_IN_SUCCESS]\n");
    } else {
        printf("[ID_IN_END]\n");
        printf("[ID_IN_ERROR]\n");
        printf("[CREATE_ERROR]\n");
        return;
    }
    id[strcspn(id, "\n")] = 0;

    printf("[SECRET_IN_START]\n");
    if (fgets(secret, 35, stdin) != NULL) {
        printf("[SECRET_IN_END]\n");
        printf("[SECRET_IN_SUCCESS]\n");
    } else {
        printf("[SECRET_IN_END]\n");
        printf("[SECRET_IN_ERROR]\n");
        printf("[CREATE_ERROR]\n");
        return;
    }
    secret[strcspn(secret, "\n")] = 0;

    printf("[DATA_IN_START]\n");
    if (fgets(data, 55, stdin) != NULL) {
        printf("[DATA_IN_END]\n");
        printf("[DATA_IN_SUCCESS]\n");
    } else {
        printf("[DATA_IN_END]\n");
        printf("[DATA_IN_ERROR]\n");
        printf("[CREATE_ERROR]\n");
        return;
    }
    data[strcspn(data, "\n")] = 0;

    fd = openat(devices_fd, id, O_CREAT | O_EXCL | O_RDWR, 0664);
    if (fd < 0) {
        if (errno == EEXIST) {
            printf("[CREATE_ERROR]\n");
            return;
        }
    }
    write(fd, &secret, strlen(secret));
    write(fd, "\n", 1);
    write(fd, &data, strlen(data));

    printf("[CREATE_SUCCESS]\n");
    return;
}

// Choosing a device (flag ID for the flag device)
void open_device(int devices_fd, device_t* current_device, device_t** pcurrent_device, device_t* devices, int* open_devices) {
    int fd;
    char id[66];
    char secret[66];
    char data[66];

    if (*open_devices >= 512) {
        printf("[MEM_FULL]\n");
        return;
    }

    printf("[IN_START]\n");
    if (fgets(id, 34, stdin) != NULL) {
        printf("[IN_END]\n");
        printf("[IN_SUCCESS]\n");
    } else {
        printf("[IN_END]\n");
        printf("[IN_ERROR]\n");
        printf("[CHOOSE_ERROR]\n");
        return;
    }
    
    id[strcspn(id, "\n")] = 0;
    fd = openat(devices_fd, id, O_RDWR, 0644);
    if (fd < 0) {
        printf("[CHOOSE_ERROR]\n");
        return;
    }
    
    ssize_t ret_value = read_line(fd, secret, 33);
    if (ret_value < 0) {
        printf("[CHOOSE_ERROR]\n");
        return;
    }
    ret_value = read_line(fd, data, 53);
    if (ret_value < 0) {
        printf("[CHOOSE_ERROR]\n");
        return;
    }

    current_device = (device_t*) &devices[*open_devices];
    if (current_device == NULL) {
        printf("[CHOOSE_ERROR]\n");
        return;
    }
    
    current_device->fd = fd;
    current_device->index = *open_devices;
    strncpy(current_device->id, id, sizeof(current_device->id));
    secret[strcspn(secret, "\x0a")] = 0;
    strncpy(current_device->secret, secret, sizeof(current_device->secret));
    data[strcspn(data, "\x0a")] = 0;
    strncpy(current_device->data, data, sizeof(current_device->data));
    current_device->unlocked = false;
    *pcurrent_device = current_device;
    *open_devices += 1;

    printf("[CHOOSE_SUCCESS]\n");
    return;
}

// Providing the secret for the current device to gain access to it
void device_secret(device_t* current_device) {
    if (current_device == NULL) {
        printf("[DEVICE_ERROR]\n");
        return;
    }

    char secret[33];
    printf("[IN_START]\n");
    if (fgets(secret, sizeof(secret), stdin) != NULL) {
        printf("[IN_END]\n");
        printf("[IN_SUCCESS]\n");
    } else {
        printf("[IN_END]\n");
        printf("[IN_ERROR]\n");
        printf("[SECRET_ERROR]\n");
        return;
    }

    secret[strcspn(secret, "\n")] = 0;
    // AUTHOR'S NOTE: 2nd vuln - if the inputted secret is of length 0,
    // then this passes without checking if they actually match
    if (memcmp(secret, current_device->secret, strlen(secret)) == 0) {
        current_device->unlocked = true;
        printf("[SECRET_SUCCESS]\n");
    } else {
        current_device->unlocked = false;
        printf("[SECRET_ERROR]\n");
    }
    return;
}

// Printing data from the current device
void device_data(device_t* current_device) {
    if (current_device == NULL) {
        printf("[DEVICE_ERROR]\n");
        return;
    }

    printf("[TEL_START]\n");
    printf("Device ID: %s\n", current_device->id);
    printf("Index: %d\n", current_device->index);
    printf("Unlocked: %s\n", (current_device->unlocked) ? "True" : "False");
    if (current_device->unlocked == true) {
        printf("Data: %s\n", current_device->data);
    }
    printf("[TEL_END]\n");
    return;
}

// Changing the current_device to a previously opened device with its index
void choose_open(int open_devices, device_t* devices, device_t** current_device) {
    long int index;
    char indexstr[5];
    printf("[IN_START]\n");
    if (fgets(indexstr, sizeof(indexstr), stdin) != NULL) {
        printf("[IN_END]\n");
        printf("[IN_SUCCESS]\n");
    } else {
        printf("[IN_END]\n");
        printf("[IN_ERROR]\n");
        printf("[CHOOSE_ERROR]\n");
        return;
    }
    indexstr[strcspn(indexstr, "\n")] = 0;

    char* endptr;
    index = strtol(indexstr, &endptr, 10);
    if (endptr == indexstr || *endptr != '\0') {
        printf("[CHOOSE_ERROR]\n");
        return;
    }

    if (index < open_devices && index >= 0) {
        *current_device = (device_t*) &devices[index];
        printf("[CHOOSE_SUCCESS]\n");
        return;
    } else {
        printf("[CHOOSE_ERROR]\n");
        return;
    }
}

// Updating the data for the current device from its file pointer
// AUTHOR'S NOTE: 3rd vuln - by getting the fd to over 0x100, 
// creating a new device with completely filled data,
// creating a new device used to leak the flag,
// updating the filled device to reread the data,
// the first byte of the fd for the leaked device gets overwritten with 0x00
// and by updating the contents of the leaked device, the data can be read
// without knowing the secret of the flag device
void device_update(device_t* current_device) {
    if (current_device == NULL) {
        printf("[DEVICE_ERROR]\n");
        return;
    }

    int fd = current_device->fd;
    char* secret = current_device->secret;
    char* data = current_device->data;

    lseek(fd, 0, SEEK_SET);
    ssize_t ret_value = read_line(fd, secret, 33);
    if (ret_value < 0) {
        printf("[UPDATE_ERROR]\n");
        return;
    }
    ret_value = read_line(fd, data, 53);
    if (ret_value < 0) {
        printf("[UPDATE_ERROR]\n");
        return;
    }

    secret[strcspn(secret, "\x0a")] = 0;
    data[strcspn(data, "\x0a")] = 0;

    printf("[UPDATE_SUCCESS]\n");
    return;
}


int main() {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
    setbuf(stderr, NULL);
    printf("[CONN_SUCCESS]\n");

    static int devices_fd = -1;
    devices_fd = open("./devices", O_DIRECTORY);
    if (devices_fd < 0) {
        printf("[OPEN_ERROR]\n");
        return 1;
    }

    static int open_devices = 0;
    static device_t devices[512];
    static device_t* current_device = NULL;

    char option;
    for(;;) {
        fread(&option, 1, 1, stdin);
        
        switch(option) {
            case(PKT_OPT_PING):
                ping();
                break;
            case(PKT_OPT_CREATE_DEVICE):
                create_device(devices_fd);
                break;
            case(PKT_OPT_OPEN_DEVICE):
                open_device(devices_fd, current_device, &current_device, devices, &open_devices);
                break;
            case(PKT_OPT_DEVICE_SECRET):
                device_secret(current_device);
                break;
            case(PKT_OPT_DEVICE_DATA):
                device_data(current_device);
                break;
            case(PKT_OPT_CHOOSE_OPEN):
                choose_open(open_devices, devices, &current_device);
                break;
            case(PKT_OPT_DEVICE_UPDATE):
                device_update(current_device);
                break;
            case(PKT_OPT_CLOSE_CONNECTION):
                printf("[CONN_CLOSED]\n");
                return 0;
            default:
                printf("[OPT_INVALID]\n");
                break;
        }
    }
}