/*
 * Project Configuration for DAO-Shield
 */

#ifndef PROJECT_CONF_H_
#define PROJECT_CONF_H_

/* Enable IPv6 */
#define UIP_CONF_IPV6 1

/* RPL Configuration */
#define UIP_CONF_ROUTER 1

/* Enable RPL */
#define NETSTACK_CONF_ROUTING_RPL_LITE 1

#define ENABLE_ATTACK 1        /* 0 = normal, 1 = attacker active */

/* Enable DAO-Shield defense (set to 0 to disable) */
#define DAO_SHIELD_ENABLED 1

/* Logging */
#define LOG_CONF_LEVEL_RPL LOG_LEVEL_DBG


/* Memory optimization */
#define UIP_CONF_BUFFER_SIZE 240
#define UIP_CONF_MAX_ROUTES 20

#endif /* PROJECT_CONF_H_ */
#define LOG_CONF_LEVEL_APP LOG_LEVEL_INFO
