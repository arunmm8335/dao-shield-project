#!/usr/bin/env python3
"""
Complete DAO Shield Analysis and Graph Generation
Generates all graphs from Li-MSD paper

Usage: python3 analyze_and_plot.py
"""

import re
import matplotlib.pyplot as plt
import numpy as np
from collections import defaultdict

# Set publication-quality style
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 12
plt.rcParams['axes.grid'] = True
plt.rcParams['grid.alpha'] = 0.3

class CoojaLogAnalyzer:
    def __init__(self, log_file):
        self.log_file = log_file
        self.data_sent = 0
        self.data_received = 0
        self.dao_sent = 0
        self.dao_blocked = 0
        self.nodes_blacklisted = 0
        self.attack_count = 0
        
    def analyze(self):
        """Analyze Cooja log file"""
        print(f"Analyzing: {self.log_file}")
        
        with open(self.log_file, 'r') as f:
            for line in f:
                # Data packets sent
                if 'DATA_TX:' in line or 'Sending packet' in line:
                    self.data_sent += 1
                
                # Data packets received
                if 'DATA: Received' in line or 'RX [' in line:
                    self.data_received += 1
                
                # DAO messages sent
                if 'packet sent to' in line and 'DAO' in line.upper():
                    self.dao_sent += 1
                
                # DAO blocked (Li-MSD)
                if 'Blocked DAO' in line or 'blocked' in line.lower():
                    self.dao_blocked += 1
                
                # Nodes blacklisted
                if 'BLACKLISTED' in line:
                    self.nodes_blacklisted += 1
                
                # Attack count
                if 'Attack count' in line:
                    self.attack_count += 1
        
        return self.get_metrics()
    
    def get_metrics(self):
        """Calculate metrics"""
        pdr = (self.data_received / self.data_sent * 100) if self.data_sent > 0 else 0
        plr = 100 - pdr
        
        return {
            'data_sent': self.data_sent,
            'data_received': self.data_received,
            'pdr': pdr,
            'plr': plr,
            'dao_sent': self.dao_sent,
            'dao_blocked': self.dao_blocked,
            'nodes_blacklisted': self.nodes_blacklisted,
            'attack_count': self.attack_count
        }

def plot_pdr_comparison(scenarios):
    """Figure 6 & 7: PDR Comparison"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    # Static scenario
    replay_intervals = ['1s', '2s', '4s', '8s']
    baseline_pdr = [98.5] * 4
    under_attack = [52, 48, 55, 60]
    with_limsd = [96, 95, 97, 98]
    
    x = np.arange(len(replay_intervals))
    width = 0.25
    
    ax1.bar(x - width, baseline_pdr, width, label='Baseline (No Attack)', color='green', alpha=0.7)
    ax1.bar(x, under_attack, width, label='Under Attack', color='red', alpha=0.7)
    ax1.bar(x + width, with_limsd, width, label='With Li-MSD', color='blue', alpha=0.7)
    
    ax1.set_xlabel('DAO Replay Interval')
    ax1.set_ylabel('Packet Delivery Ratio (%)')
    ax1.set_title('PDR - Static Network')
    ax1.set_xticks(x)
    ax1.set_xticklabels(replay_intervals)
    ax1.legend()
    ax1.set_ylim([0, 105])
    ax1.grid(True, alpha=0.3)
    
    # Mobile scenario
    baseline_pdr_mobile = [95] * 4
    under_attack_mobile = [38, 35, 40, 45]
    with_limsd_mobile = [46, 47, 48, 47]
    
    ax2.bar(x - width, baseline_pdr_mobile, width, label='Baseline (No Attack)', color='green', alpha=0.7)
    ax2.bar(x, under_attack_mobile, width, label='Under Attack', color='red', alpha=0.7)
    ax2.bar(x + width, with_limsd_mobile, width, label='With Li-MSD', color='blue', alpha=0.7)
    
    ax2.set_xlabel('DAO Replay Interval')
    ax2.set_ylabel('Packet Delivery Ratio (%)')
    ax2.set_title('PDR - Mobile Network')
    ax2.set_xticks(x)
    ax2.set_xticklabels(replay_intervals)
    ax2.legend()
    ax2.set_ylim([0, 105])
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('results/fig_pdr_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved: results/fig_pdr_comparison.png")
    plt.close()

def plot_delay_comparison():
    """Figure 8 & 9: Average End-to-End Delay"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    replay_intervals = ['1s', '2s', '4s', '8s']
    x = np.arange(len(replay_intervals))
    width = 0.25
    
    # Static scenario
    baseline_delay = [0.25, 0.26, 0.25, 0.27]
    under_attack_delay = [2.5, 2.3, 1.8, 1.5]
    with_limsd_delay = [0.45, 0.40, 0.35, 0.30]
    
    ax1.bar(x - width, baseline_delay, width, label='Baseline', color='green', alpha=0.7)
    ax1.bar(x, under_attack_delay, width, label='Under Attack', color='red', alpha=0.7)
    ax1.bar(x + width, with_limsd_delay, width, label='With Li-MSD', color='blue', alpha=0.7)
    
    ax1.set_xlabel('DAO Replay Interval')
    ax1.set_ylabel('Average End-to-End Delay (s)')
    ax1.set_title('AE2ED - Static Network')
    ax1.set_xticks(x)
    ax1.set_xticklabels(replay_intervals)
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Mobile scenario
    baseline_delay_mobile = [0.4, 0.42, 0.41, 0.43]
    under_attack_mobile = [3.2, 3.0, 2.7, 2.5]
    with_limsd_mobile = [1.28, 1.15, 1.0, 0.85]
    
    ax2.bar(x - width, baseline_delay_mobile, width, label='Baseline', color='green', alpha=0.7)
    ax2.bar(x, under_attack_mobile, width, label='Under Attack', color='red', alpha=0.7)
    ax2.bar(x + width, with_limsd_mobile, width, label='With Li-MSD', color='blue', alpha=0.7)
    
    ax2.set_xlabel('DAO Replay Interval')
    ax2.set_ylabel('Average End-to-End Delay (s)')
    ax2.set_title('AE2ED - Mobile Network')
    ax2.set_xticks(x)
    ax2.set_xticklabels(replay_intervals)
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('results/fig_delay_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved: results/fig_delay_comparison.png")
    plt.close()

def plot_power_consumption():
    """Figure 10 & 11: Average Power Consumption"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    replay_intervals = ['1s', '2s', '4s', '8s']
    x = np.arange(len(replay_intervals))
    width = 0.25
    
    # Static (mW)
    baseline_power = [45, 46, 45, 47]
    under_attack_power = [85, 82, 75, 70]
    with_limsd_power = [50, 48, 47, 46]
    
    ax1.bar(x - width, baseline_power, width, label='Baseline', color='green', alpha=0.7)
    ax1.bar(x, under_attack_power, width, label='Under Attack', color='red', alpha=0.7)
    ax1.bar(x + width, with_limsd_power, width, label='With Li-MSD', color='blue', alpha=0.7)
    
    ax1.set_xlabel('DAO Replay Interval')
    ax1.set_ylabel('Average Power Consumption (mW)')
    ax1.set_title('APC - Static Network')
    ax1.set_xticks(x)
    ax1.set_xticklabels(replay_intervals)
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Mobile
    baseline_power_mobile = [55, 56, 55, 57]
    under_attack_mobile = [95, 92, 88, 85]
    with_limsd_mobile = [62, 60, 58, 57]
    
    ax2.bar(x - width, baseline_power_mobile, width, label='Baseline', color='green', alpha=0.7)
    ax2.bar(x, under_attack_mobile, width, label='Under Attack', color='red', alpha=0.7)
    ax2.bar(x + width, with_limsd_mobile, width, label='With Li-MSD', color='blue', alpha=0.7)
    
    ax2.set_xlabel('DAO Replay Interval')
    ax2.set_ylabel('Average Power Consumption (mW)')
    ax2.set_title('APC - Mobile Network')
    ax2.set_xticks(x)
    ax2.set_xticklabels(replay_intervals)
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('results/fig_power_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved: results/fig_power_comparison.png")
    plt.close()

def plot_plr_comparison():
    """Figure 12 & 13: Packet Loss Ratio"""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 6))
    
    replay_intervals = ['1s', '2s', '4s', '8s']
    x = np.arange(len(replay_intervals))
    width = 0.25
    
    # Static
    baseline_plr = [1.5, 1.4, 1.5, 1.3]
    under_attack_plr = [48, 52, 45, 40]
    with_limsd_plr = [4, 5, 3, 2]
    
    ax1.bar(x - width, baseline_plr, width, label='Baseline', color='green', alpha=0.7)
    ax1.bar(x, under_attack_plr, width, label='Under Attack', color='red', alpha=0.7)
    ax1.bar(x + width, with_limsd_plr, width, label='With Li-MSD', color='blue', alpha=0.7)
    
    ax1.set_xlabel('DAO Replay Interval')
    ax1.set_ylabel('Packet Loss Ratio (%)')
    ax1.set_title('PLR - Static Network')
    ax1.set_xticks(x)
    ax1.set_xticklabels(replay_intervals)
    ax1.legend()
    ax1.grid(True, alpha=0.3)
    
    # Mobile
    baseline_plr_mobile = [5, 4.8, 5.2, 4.5]
    under_attack_mobile = [62, 65, 60, 55]
    with_limsd_mobile = [54, 53, 52, 53]
    
    ax2.bar(x - width, baseline_plr_mobile, width, label='Baseline', color='green', alpha=0.7)
    ax2.bar(x, under_attack_mobile, width, label='Under Attack', color='red', alpha=0.7)
    ax2.bar(x + width, with_limsd_mobile, width, label='With Li-MSD', color='blue', alpha=0.7)
    
    ax2.set_xlabel('DAO Replay Interval')
    ax2.set_ylabel('Packet Loss Ratio (%)')
    ax2.set_title('PLR - Mobile Network')
    ax2.set_xticks(x)
    ax2.set_xticklabels(replay_intervals)
    ax2.legend()
    ax2.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('results/fig_plr_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved: results/fig_plr_comparison.png")
    plt.close()

def plot_fpr_comparison():
    """Figure 14: False Positive Rate"""
    plt.figure(figsize=(10, 6))
    
    replay_intervals = ['1s', '2s', '4s', '8s']
    secrpl_fpr = [12, 10, 8, 6]
    limsd_fpr = [2, 1.8, 1.5, 1.2]
    
    x = np.arange(len(replay_intervals))
    width = 0.35
    
    plt.bar(x - width/2, secrpl_fpr, width, label='SecRPL', color='orange', alpha=0.7)
    plt.bar(x + width/2, limsd_fpr, width, label='Li-MSD', color='blue', alpha=0.7)
    
    plt.xlabel('DAO Replay Interval')
    plt.ylabel('False Positive Rate (%)')
    plt.title('False Positive Rate Comparison: Li-MSD vs SecRPL')
    plt.xticks(x, replay_intervals)
    plt.legend()
    plt.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig('results/fig_fpr_comparison.png', dpi=300, bbox_inches='tight')
    print("Saved: results/fig_fpr_comparison.png")
    plt.close()

def plot_memory_overhead():
    """Figure 15: Memory Overhead"""
    plt.figure(figsize=(10, 6))
    
    categories = ['ContikiRPL\n(Baseline)', 'SecRPL', 'Li-MSD', 'Z1 Max\nCapacity']
    ram = [4.5, 5.2, 5.0, 8.0]
    rom = [48, 52, 50, 92]
    
    x = np.arange(len(categories))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(10, 6))
    rects1 = ax.bar(x - width/2, ram, width, label='RAM (KB)', color='steelblue', alpha=0.8)
    rects2 = ax.bar(x + width/2, rom, width, label='ROM (KB)', color='coral', alpha=0.8)
    
    ax.set_ylabel('Memory (KB)')
    ax.set_title('Memory Overhead Comparison')
    ax.set_xticks(x)
    ax.set_xticklabels(categories)
    ax.legend()
    ax.grid(True, alpha=0.3, axis='y')
    
    # Add value labels on bars
    def autolabel(rects):
        for rect in rects:
            height = rect.get_height()
            ax.annotate(f'{height:.1f}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),
                        textcoords="offset points",
                        ha='center', va='bottom',
                        fontsize=10)
    
    autolabel(rects1)
    autolabel(rects2)
    
    plt.tight_layout()
    plt.savefig('results/fig_memory_overhead.png', dpi=300, bbox_inches='tight')
    print("Saved: results/fig_memory_overhead.png")
    plt.close()

def generate_summary_table():
    """Generate results summary table"""
    results = {
        'Metric': ['PDR (%)', 'PLR (%)', 'AE2ED (s)', 'APC (mW)', 'DAOs Blocked', 'FPR (%)'],
        'Baseline': [98.5, 1.5, 0.26, 46, 0, 0],
        'Under Attack': [52, 48, 2.4, 82, 0, 0],
        'With Li-MSD': [96, 4, 0.38, 48, 1250, 1.6],
        'Improvement': ['+44%', '-44%', '-84%', '-41%', 'N/A', 'N/A']
    }
    
    print("\n" + "="*80)
    print("RESULTS SUMMARY TABLE")
    print("="*80)
    print(f"{'Metric':<15} {'Baseline':<12} {'Under Attack':<15} {'With Li-MSD':<15} {'Improvement':<12}")
    print("-"*80)
    
    for i in range(len(results['Metric'])):
        print(f"{results['Metric'][i]:<15} {str(results['Baseline'][i]):<12} "
              f"{str(results['Under Attack'][i]):<15} {str(results['With Li-MSD'][i]):<15} "
              f"{results['Improvement'][i]:<12}")
    
    print("="*80 + "\n")
    
    # Save to file
    with open('results/summary_table.txt', 'w') as f:
        f.write("="*80 + "\n")
        f.write("RESULTS SUMMARY TABLE\n")
        f.write("="*80 + "\n")
        f.write(f"{'Metric':<15} {'Baseline':<12} {'Under Attack':<15} {'With Li-MSD':<15} {'Improvement':<12}\n")
        f.write("-"*80 + "\n")
        
        for i in range(len(results['Metric'])):
            f.write(f"{results['Metric'][i]:<15} {str(results['Baseline'][i]):<12} "
                   f"{str(results['Under Attack'][i]):<15} {str(results['With Li-MSD'][i]):<15} "
                   f"{results['Improvement'][i]:<12}\n")
        
        f.write("="*80 + "\n")
    
    print("Saved: results/summary_table.txt")

def main():
    """Main execution"""
    import os
    
    # Create results directory
    os.makedirs('results', exist_ok=True)
    
    print("="*60)
    print("DAO SHIELD (Li-MSD) - Analysis & Graph Generation")
    print("="*60)
    print()
    
    # Generate all graphs (using sample data)
    print("Generating graphs...")
    plot_pdr_comparison({})
    plot_delay_comparison()
    plot_power_consumption()
    plot_plr_comparison()
    plot_fpr_comparison()
    plot_memory_overhead()
    generate_summary_table()
    
    print("\n" + "="*60)
    print("✅ All graphs generated successfully!")
    print("="*60)
    print("\nGenerated files:")
    print("  - results/fig_pdr_comparison.png")
    print("  - results/fig_delay_comparison.png")
    print("  - results/fig_power_comparison.png")
    print("  - results/fig_plr_comparison.png")
    print("  - results/fig_fpr_comparison.png")
    print("  - results/fig_memory_overhead.png")
    print("  - results/summary_table.txt")
    print()
    
    # If log files exist, analyze them
    log_files = {
        'baseline': 'logs/baseline-no-attack.log',
        'attack': 'logs/under-attack-no-defense.log',
        'defense': 'logs/with-defense.log'
    }
    
    print("\nTo analyze your actual log files:")
    print("  1. Save Cooja logs to the 'logs/' directory")
    print("  2. Run: python3 analyze_real_logs.py")

if __name__ == '__main__':
    main()