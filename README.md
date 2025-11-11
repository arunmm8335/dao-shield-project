# Li-MSD: A Resilient Shield for RPL DAO Attacks

This project designs, implements, and analyzes a lightweight intrusion detection system (IDS) called **Li-MSD (Lightweight Malicious-DAO Shield)** to protect IoT networks using the RPL routing protocol from Denial of Service (DoS) attacks.

The experiment uses the Contiki-NG operating system and the Cooja simulator to demonstrate the vulnerability and test the shield's effectiveness.

## 1. The Problem: DAO Attacks
RPL (Routing Protocol for Low-Power and Lossy Networks) relies on unauthenticated **Destination Advertisement Object (DAO)** messages for routing. This creates two major vulnerabilities:
1.  **"No-path" Attack:** An attacker can flood the root with `lifetime 0` DAOs, forcing it to constantly delete its routes and causing network instability.
2.  **IP Spoofing Attack:** A sophisticated attacker can send DAOs *impersonating* legitimate nodes. A naive defense system can be tricked into blacklisting these innocent nodes, turning the shield into the very tool of the DoS.

## 2. Project Structure
The project is structured with a specific Contiki-NG project folder and one modification to the core OS files.

### Project Folder (`/home/roy1916/contiki-ng/examples/dao-shield-project`)
* `root-node.c`: Firmware for the `mtype1` (ID 1) DODAG Root. It listens for and logs client data.
* `client-node.c`: Firmware for the `mtype2` (IDs 2-6) benign nodes. They join the network and send "Hello" packets to the root.
* [cite_start]`attacker-node.c`: [cite: 4] Firmware for the `mtype3` (ID 7) malicious node. When enabled, it performs a "No-path" DAO flood attack (`rpl_icmp6_dao_output(0)`).
* [cite_start]`project-conf.h`: [cite: 1] **(CRITICAL)** The configuration file used to switch between experimental scenarios.
* [cite_start]`dao-baseline.csc`: [cite: 2] The Cooja simulation file, defining the 7-node topology.

### Core OS Modification (`/home/roy1916/contiki-ng/os/net/routing/rpl-lite/`)
* [cite_start]`rpl-dag.c`: [cite: 3] This core RPL file was modified to insert the **Li-MSD shield** logic. The shield hooks into the `rpl_process_dao` function to intercept and validate every DAO packet.

## 3. How to Run the Experiment
[cite_start]Load the `dao-baseline.csc` [cite: 2] simulation file in Cooja. [cite_start]The three experimental scenarios can be run by changing two macros in `project-conf.h` [cite: 1] and recompiling.

```c
/* project-conf.h */

#define ENABLE_ATTACK 1        /* 0 = normal, 1 = attacker active */
#define DAO_SHIELD_ENABLED 1   /* 0 = normal, 1 = attacker active */
```

### Scenario 1: Baseline (Normal Operation)
* **Purpose:** Observe a healthy network.
* **Settings:**
    ```c
    #define ENABLE_ATTACK 0
    #define DAO_SHIELD_ENABLED 0
    ```
* **Result:** All client nodes join the network and send data. The root log (`root-node.c`) shows successful data reception.

### Scenario 2: Attack (No Shield)
* **Purpose:** Demonstrate the "No-path" attack's impact.
* **Settings:**
    ```c
    #define ENABLE_ATTACK 1
    #define DAO_SHIELD_ENABLED 0
    ```
* **Result:** The attacker (ID 7) floods the root. The root's log is filled with `[DBG : RPL ] DAO with lifetime 0, expiring route`. Network performance degrades severely.

### Scenario 3: Attack (With Li-MSD Shield)
* **Purpose:** Test the shield's effectiveness.
* **Settings:**
    ```c
    #define ENABLE_ATTACK 1
    #define DAO_SHIELD_ENABLED 1
    ```
* [cite_start]**Result:** The Li-MSD logic in `rpl-dag.c` [cite: 3] becomes active and begins blocking the malicious DAOs.

## 4. Implementation & Analysis of Li-MSD

### Iteration 1: The Flawed (Permanent) Blacklist
The initial implementation (present in `rpl-dag.c`) used a simple threshold and a permanent blacklist.

```c
/*
 * File: rpl-dag.c (Iteration 1 Implementation)
 */
#define DAO_THRESHOLD 5      /* β: Max DAOs before blacklisting */
...
typedef struct {
  uip_ipaddr_t node_addr;
  uint8_t used;
} blacklist_entry_t;
...
static void
limsd_add_to_blacklist(const uip_ipaddr_t *addr)
{
  ...
  for(int i = 0; i < MAX_BLACKLIST; i++) {
    if(!blacklist[i].used) {
      uip_ipaddr_copy(&blacklist[i].node_addr, addr);
      blacklist[i].used = 1; /* <-- Permanent blacklist */
      ...
    }
  }
}
```

**Analysis (The Critical Flaw):** This design was vulnerable to an **IP Spoofing Attack**.
* The attacker (ID 7) switched from a simple flood to spoofing the IPs of legitimate nodes (e.g., ID 3).
* The shield was fooled and added the *innocent* node (ID 3) to the permanent blacklist.
* **Evidence:** The log file `new_run._attacker_enabled_sheild_enabled.txt` shows:
    * **Root (ID 1):** `ID:1 [INFO: RPL ] Li-MSD: ﾜﾖ Blocked DAO #127466 from blacklisted fd00::203:3:3:3`
    * **Victim (ID 3):** `ID:3 [WARN: Client ] No route to root yet (reachable=0)`
* **Conclusion:** The shield itself became the tool for a *Persistent* DoS.

### Iteration 2: The Resilient (Temporary) Blacklist
To fix this, the shield was redesigned to use a **temporary blacklist**. The `blacklist_entry_t` struct was modified to include a `struct ctimer`, and `limsd_add_to_blacklist` was updated to set a 60-second timeout. This allows the shield to block an attack but ensures that any innocent, blacklisted nodes are automatically "pardoned" and can rejoin the network.

## 5. Quantitative Results
The following results were collected using the **final, resilient (Iteration 2)** shield.

| Metric | Baseline | Under Attack | With Li-MSD (Final) | Improvement |
| :--- | :---: | :---: | :---: | :---: |
| **PDR (%)** | 98.5 | 52 | **96** | **+44%** |
| **PLR (%)** | 1.5 | 48 | **4** | **-44%** |
| **AE2ED (s)** | 0.26 | 2.4 | **0.38** | **-84%** |
| **APC (mW)** | 46 | 82 | **48** | **-41%** |
| **DAOs Blocked** | 0 | 0 | **1250** | N/A |
| **FPR (%)** | 0 | 0 | **1.6** | N/A |

*(Data from `summary_table.txt`)*

**Analysis:**
* **Performance:** The attack was devastating, cutting the **PDR** to 52% and nearly doubling **power consumption (APC)**. The final Li-MSD shield restored network performance to near-baseline levels (96% PDR).
* **Resilience (FPR):** The **False Positive Rate of 1.6%** shows that the shield *did* (as expected) incorrectly block some legitimate nodes. However, because this blocking was **temporary**, the nodes could recover, resulting in the high 96% PDR. This proves the success of the Iteration 2 design.

## 6. Conclusion
This project demonstrates that a naive, stateless security shield is not only ineffective but actively dangerous. By analyzing the failure of our first implementation, we developed a resilient **Li-MSD with a temporary blacklist**. This final design successfully mitigates sophisticated attacks, balancing security with network availability, as proven by the 44% improvement in PDR.
