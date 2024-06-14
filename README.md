# Emulating EDR Cyber Attack and Defence

## Project Overview 
This lab simulates a real-world cyber-attack and Endpoint Detection and Response (EDR) scenario, following Eric Capuano's guide. Both the adversary and the end user are set up on Virtual Machines. The adversary uses 'Sliver' as a C2 payload to attack a Windows end user, while LimaCharlie monitors and responds as the EDR tool. Perfect for gaining hands-on experience in cybersecurity attack and defence.

Eric Capuano's Guide: https://blog.ecapuano.com/p/so-you-want-to-be-a-soc-analyst-intro?utm_campaign=post&utm_medium=web

## Lab Setup
Firstly, I'll be setting up the adversary's Virtual Machine and the User's Virtual Machine. The adversary's Virtual Machine will be running on an Ubuntu Server and the User will be running on the Windows 11 OS. To be able to simulate this attack, I am going to disable Microsoft Defender and a few other settings. 

The next step will be installing Sliver on the Ubuntu machine as our C2 attack tool and using LimaCharlie on the Windows machine to monitor and respond as my EDR tool. LimaCharlie will have a sensor connected to the Windows machine which will import the Sysmon logs it records. 

## 1. Install Sliver on Ubuntu Machine:

Download and install Sliver, the Command and Control (C2) attack tool.
Configure Sliver to prepare for launching cyber attacks on the target Windows machine.
![5  install and begin malware and c2 payload ](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/a59df777-4f6d-4082-a28c-8728456ad730)




## 2. Set Up  on Windows Machine:

Configure the Windows Machine by disabling Microsoft Defender and a few other settings, thus allowing the lab to run smoothly. 
Install Sysmon on the Windows machine which will log system activity to the Windows event log. It provides detailed information about process creations, network connections, file creation time changes, and more, which is crucial for security monitoring and incident response. 

![1  Disable Microsoft Defender and others](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/1f1e3737-f92c-43d5-8717-6887c31f427f)
![4  Disbale some more services via registry editor in  safemode ](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/5e75af19-8fce-4b9d-9481-8e0cd53ae9ab)






## 3. Connect LimaCharlie Sensor:

Deploy a LimaCharlie sensor on the Windows machine.
Configure the sensor to import the Sysmon logs from the Windows machine to the EDR, providing detailed monitoring and analysis of system activities.

![Screenshot 2024-06-14 at 12 14 00 PM](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/ced412e2-047b-463e-8a5b-e12f673f8ae2)
![Screenshot 2024-06-14 at 12 19 55 PM](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/903fbd7b-19d3-4ac0-b2b8-c36e99480d7a)




## Simulate Attacks/Defence

For this attack, I will be controlling the Ubuntu machine using SSH from my own computer. 
Next, I will generate a payload (STABLE_SHOE.exe) on the Ubuntu machine using Sliver and confirm that the new payload was created. 
Then I'll download the payload onto the Windows machine and run the payload allowing us to see that 'ALIVE' from the Adversaries side. 

![6  Connect to linux vm via ssh from personal computer ](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/2e182b78-98f4-4c67-b296-db3a953c6cb1)
![7  c2 session payload confirmation ](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/ca835efa-b2c6-4cb6-9064-297f9a08bae7)
![Screenshot 2024-06-14 at 12 46 39 PM](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/64c74647-2625-455b-87c5-4f88ee1a514a)
![8](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/5096b95f-52b1-4072-9acd-73f876b8a78f)

### Peek through the attack and gather more information 
From here the adversary's machine can easily look through the user's host information, privileges, connections and even the security that the user is running. 

Note: 
- 'rphcp.exe' is LimaCharlie EDR's executable service.
- Sliver will cleverly highlight their corresponding payloads/connections/files in green when you look through the machine. 
![9  Get information](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/c65f665f-afd6-45cf-8a16-29827a13f8d6)
![9  netstat and see the established connection in green](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/e97213be-9b0d-42a0-96cf-bcecd7cf7b4d)


### See the attacker's telemetry on LimaCharlie

On LimaCharlie, I am able to see the processes running and even see the payload itself within the processes.

I can even see the established connection it has with the adversaries IP address. 

![10  see payload is live and listening ](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/8e60c67e-8ae8-4f71-97b1-c7d759a80941)

![10 4 see many network connections to the ip and attacker payload to ip](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/6c9dff31-4439-4104-8d50-8b35600eb614)![10 3 See established connection to the Ubuntu VM IP](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/9b64e960-2d1c-4687-9f5b-d423c721f19a)


### Check the hash of the payload from LimaCharlie against VirusTotal 

Since this is a fairly new payload we just created, we won't see any results on VirusTotal

Note:
- When we 'scan' with VirusTotal, it is querying against its database to find a match. Even if the file is 'not found', it doesn't mean the file is safe.
- VirusTotal has nearly seen everything, so the fact that this file is 'not found' makes it even more suspicious than it already is.

![10 4 inspect the sus file to virustotal ](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/51b880f2-6c44-4749-b82b-aab296c44185)

### See the telemetry when we dump the credentials from LSASS 

From the Adversary's machine, we can simulate an attack to steal credentials by dumping the LSASS memory. This would allow attackers to privilege escalate and even perform pass-the-hash attacks if they were successful. For this simulation, we get an error on the adversary's machine but it will still provide us with the telemetry we need to see on LimaCharlie. 


![11  Do Dump of LSASS and see it in sensitive process ](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/a5fd1870-5a9f-432c-84be-5c6faf250dd2)

![Screenshot 2024-06-14 at 1 40 55 PM](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/affc01a5-fa6e-4117-8f31-b2a9de7eb815)

### Create a rule to detect the use of LSASS dumps

We can now create a rule for this to be able to send a detection alert on the EDR for this LSASS access. 

![13  rule added to edr](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/526fe383-7522-4be2-adb3-83a06b78fa20)
![15  rule works](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/61940ce5-7f8c-4ae7-959b-bccb45962528)

### Block an attack using LimaCharlie

Instead of just detecting an attack we will be detecting and blocking the attack from the adversary. In this part of the simulation, we will use the Sliver server to simulate a part of a ransomware attack where the attacker would attempt to delete the Volume Shadow Copies (A snapshot or backup of computer files/data from a specific point in time). Once we view the telemetry on LimaCharlie we can create the rule to detect and block the attack. Thus, the attacker will not be able to succeed in the attack again. 

<img width="881" alt="Screenshot 2024-06-14 at 3 28 34 PM" src="https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/4cc163be-1403-4fba-9a80-9ccd15768bae">

<img width="1195" alt="Screenshot 2024-06-14 at 3 25 32 PM" src="https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/cfbf41b2-9f7a-41f4-973b-4d88653a53f8">

![18  commands from attacker for VSS deletion and whoami doesnt work](https://github.com/SteveSunny46/Emulating-EDR-Cyber-Attack-and-Defence/assets/171859383/6ef00228-96f9-452d-a100-3c3fb4b1785f)


