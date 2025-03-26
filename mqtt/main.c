#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "ztimer.h"
#include "thread.h"
#include "paho_mqtt.h"
#include "MQTTClient.h"

#define BUF_SIZE                1024
#define MQTT_VERSION_v311       4       /* MQTT v3.1.1 version is 4 wie es in der paho_example steht*/
#define COMMAND_TIMEOUT_MS      4000

#define BROKER_IP               "2001:db8:1::1"  // localdevice IPv6 address
#define BROKER_PORT             1883
#define CLIENT_ID               "riot_mqtt_client"
#define TOPIC                   "/topic"
#define CHECK_INTERVAL          (60 * 1000U) // 1 min

#define DEFAULT_KEEPALIVE_SEC   10
#define IS_CLEAN_SESSION        1

static MQTTClient client;
static Network network;
static char thread_stack[THREAD_STACKSIZE_MAIN];
static unsigned char buf[BUF_SIZE];
static unsigned char readbuf[BUF_SIZE];

static void _on_msg_received(MessageData *data)
{
    printf("New data from topic %.*s: %.*s\n",
           (int)data->topicName->lenstring.len,
           data->topicName->lenstring.data,
           (int)data->message->payloadlen,
           (char *)data->message->payload);
}

static void *mqtt_thread(void *arg)
{
    (void)arg;

    // Initialize the network
    NetworkInit(&network);

    // Connect to the network
    printf("Connecting to MQTT broker at %s PORT: %d\n", BROKER_IP, BROKER_PORT);
    int ret = NetworkConnect(&network, BROKER_IP, BROKER_PORT);
    if (ret < 0) {
        printf("Unable to connect to network: %d\n", ret);
        return NULL;
    }

    // Initialize the MQTT client
    MQTTClientInit(&client, &network, COMMAND_TIMEOUT_MS,
                   buf, BUF_SIZE, readbuf, BUF_SIZE);

    // Connect data
    MQTTPacket_connectData data = MQTTPacket_connectData_initializer;
    data.MQTTVersion = MQTT_VERSION_v311;
    data.clientID.cstring = CLIENT_ID;
    data.keepAliveInterval = DEFAULT_KEEPALIVE_SEC;
    data.cleansession = IS_CLEAN_SESSION;
    data.willFlag = 0;

    // Connect the client
    ret = MQTTConnect(&client, &data);
    if (ret < 0) {
        printf("Unable to connect client: %d\n", ret);
        NetworkDisconnect(&network);
        return NULL;
    }

    printf("Connected to MQTT broker\n");

    // Start the MQTT task
    MQTTStartTask(&client);

    // Subscribe to the topic
    printf("Subscribing to topic: %s\n", TOPIC);
    ret = MQTTSubscribe(&client, TOPIC, QOS0, _on_msg_received);
    if (ret < 0) {
        printf("Unable to subscribe: %d\n", ret);
        MQTTDisconnect(&client);
        NetworkDisconnect(&network);
        return NULL;
    }

    printf("Successfully subscribed to topic %s\n", TOPIC);

    // Main loop - check every minute for updates
    while (1) {
        ztimer_sleep(ZTIMER_MSEC, CHECK_INTERVAL);
        printf("Minute passed, waiting for updates on topic %s\n", TOPIC);

        // No need to manually check - Paho MQTT will call _on_msg_received when messages arrive
    }

    return NULL;
}

int main(void)
{
    printf("Starting Paho MQTT client...\n");
    // ztimer_init();

    // Create thread for MQTT client
    thread_create(thread_stack, sizeof(thread_stack),
                  THREAD_PRIORITY_MAIN - 1,
                  THREAD_CREATE_STACKTEST,
                  mqtt_thread, NULL, "mqtt");

    // Main thread can do other things...
    while (1) {
        ztimer_sleep(ZTIMER_MSEC, 1000);
    }

    return 0;
}
