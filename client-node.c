/*
 * Fixed RPL Client Node
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/netstack.h"
#include "net/ipv6/simple-udp.h"
#include "sys/log.h"

#define LOG_MODULE "Client"
#define LOG_LEVEL LOG_LEVEL_INFO

#define UDP_CLIENT_PORT 8765
#define UDP_SERVER_PORT 5678
#define SEND_INTERVAL (60 * CLOCK_SECOND)

static struct simple_udp_connection udp_conn;
static uint32_t tx_count = 0;
static uint32_t rx_count = 0;

PROCESS(client_node_process, "RPL Client Node");
AUTOSTART_PROCESSES(&client_node_process);

/*---------------------------------------------------------------------------*/
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
  LOG_INFO("ACK: Received response #%lu from ", (unsigned long)rx_count);
  LOG_INFO_6ADDR(sender_addr);
  LOG_INFO_("\n");
}

/*---------------------------------------------------------------------------*/
PROCESS_THREAD(client_node_process, ev, data)
{
  static struct etimer periodic_timer;
  static struct etimer wait_timer;
  uip_ipaddr_t dest_ipaddr;
  char buf[64];
  
  PROCESS_BEGIN();
  
  LOG_INFO("=== Client Node Started ===\n");
  
  /* Register UDP connection */
  simple_udp_register(&udp_conn, UDP_CLIENT_PORT, NULL,
                     UDP_SERVER_PORT, udp_rx_callback);
  
  /* Wait for network to stabilize */
  LOG_INFO("Waiting 30 seconds for network formation...\n");
  etimer_set(&wait_timer, 30 * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&wait_timer));
  
  LOG_INFO("Starting periodic data transmission\n");
  
  /* Set periodic timer */
  etimer_set(&periodic_timer, SEND_INTERVAL);
  
  while(1) {
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&periodic_timer));
    
    /* Check if we have a route to root */
    if(NETSTACK_ROUTING.node_is_reachable() &&
       NETSTACK_ROUTING.get_root_ipaddr(&dest_ipaddr)) {
      
      /* Prepare data packet */
      snprintf(buf, sizeof(buf), "Hello %lu from node", (unsigned long)tx_count);
      tx_count++;
      
      LOG_INFO("DATA_TX: Sending packet #%lu to root at time %lu\n", 
               (unsigned long)tx_count, clock_time());
      
      /* Send UDP packet */
      simple_udp_sendto(&udp_conn, buf, strlen(buf), &dest_ipaddr);
      
    } else {
      LOG_WARN("No route to root yet (reachable=%d)\n", 
               NETSTACK_ROUTING.node_is_reachable());
    }
    
    /* Reset timer for next transmission */
    etimer_reset(&periodic_timer);
  }
  
  PROCESS_END();
}
