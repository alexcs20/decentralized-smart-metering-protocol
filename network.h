#ifndef NETWORK_H
#define NETWORK_H

#include <stdint.h>
#include "config.h"

typedef enum {
    MSG_COMMITMENT,
    MSG_REVEAL,
    MSG_READING_COMMITMENT,
    MSG_SHARE,
    MSG_AGGREGATED_SHARE,
    MSG_FINAL_RESULT
} MessageType;

typedef struct {
    MessageType type;
    uint8_t sender_id;
    uint32_t round;
    uint32_t timestamp;
    uint8_t data[MAX_MESSAGE_SIZE];
    size_t data_len;
} NetworkMessage;

int network_init(uint8_t meter_id);
int network_broadcast(NetworkMessage *msg);
int network_send_to(uint8_t destination, NetworkMessage *msg);
int network_receive(uint8_t meter_id, NetworkMessage *msg, int timeout_ms);

#endif
