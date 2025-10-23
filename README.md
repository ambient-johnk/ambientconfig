*Used to check a linux server for proper status and perform basic configurations.

Instructions:
1. Change to a protected directory like roots home folder (example: /root)

2. Clone repo to folder:
git clone https://github.com/ambient-johnk/ambientconfig

3. Change to ambientconfig directory

4. CHMOD file permissions to 700      

5. !!This is a BASH script so you must use BASH as SUDO!!
   "sudo bash ambientconfig.sh"


======================================
          AmbientOS Appliance         
      System Configuration Script     
      version 0.13 - 10232025 - jk    
======================================
System Verification:
  1. Pre-Flight: Verify Basic System Requirements

Hardware Verification:
  2. Check Network Interfaces
  3. Check NVIDIA GPU & Drivers
  4. Check CPU Info
  5. Check Memory Modules
  6. Check Power Supplies
  7. Check RAID Controller
  8. Run ALL Hardware Checks

System Configuration:
  9.  Configure Netplan
  10. Configure Timezone
  11. Format and Mount Volume

Reporting:
  12. Generate Full System Report (Archive)
  13. View Recent Reports

  14. Run Everything
  99. Exit
