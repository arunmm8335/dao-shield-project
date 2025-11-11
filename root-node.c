/*
 * RPL Root Node
 */

#include "contiki.h"
#include "simple-energest.h"
#include "net/routing/routing.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"

#define LOG_MODULE "Root"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_SERVER_PORT 5678
#define UDP_CLIENT_PORT 8765

static struct simple_udp_connection udp_conn;
static uint32_t rx_count = 0;

PROCESS(root_node_process, "RPL Root");
AUTOSTART_PROCESSES(&root_node_process);

static void
udp_rx_callback(struct simple_udp_connection *c,
                const uip_ipaddr_t *sender_addr,
                uint16_t sender_port,
                const uip_ipaddr_t *receiver_addr,
                uint16_t receiver_port,
                const uint8_t *data,
                uint16_t datalen)
{
  rx_count++;
  LOG_INFO("DATA: Received at time %lu ticks\n", clock_time());
  LOG_INFO("RX [%lu]: received %u bytes: %.*s\n", (unsigned long)rx_count, datalen, datalen, (char *)data);

}
PROCESS_THREAD(root_node_process, ev, data)
{
  static struct etimer timer;
  
  PROCESS_BEGIN();
  simple_energest_init();
  
  LOG_INFO("Root node starting\n");
  
  NETSTACK_ROUTING.root_start();
  
  simple_udp_register(&udp_conn, UDP_SERVER_PORT, NULL,
                     UDP_CLIENT_PORT, udp_rx_callback);
  
  LOG_INFO("Root ready\n");
  
  etimer_set(&timer, 60 * CLOCK_SECOND);
  
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&timer));
    LOG_INFO("=== Stats: RX=%lu ===\n", (unsigned long)rx_count);
    etimer_reset(&timer);
  }
  
  PROCESS_END();
}
