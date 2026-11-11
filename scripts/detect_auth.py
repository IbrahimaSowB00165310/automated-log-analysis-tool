import re
import os
from collections import Counter, defaultdict


#auth.log file path
current_dir= os.path.dirname(__file__)
mylog_file_path = os.path.join(current_dir, "..", "auth.log")#building to the auth.log file

ips = [] # a list to store suspecious IPs
ip_times = defaultdict(list)#dictionary to store timesatamp of each attempt per IP
total_high = 0
total_medium = 0
total_attempts = 0

with open(mylog_file_path, "r", encoding = "utf-8", errors = "ignore") as f: #opening the file to read it
     l = f.readlines()
     
for line in l: #looping through the file line by line
    #checking failed SSH loging in the line
    if "Failed password" in line or "maximum authentication attempts exceeded" in line:
        ip_match = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", line) #extracting IP address using regex
        time_match = re.search(r"^(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})", line) #extracting timestamp using regex
        if ip_match: #if an IP is found 
            the_ip = ip_match.group(1)
            ips.append(the_ip) #adding it to the list
            if time_match:  # if timestamp is found, store it for that IP
                log_time = time_match.group(1)
                ip_times[the_ip].append(log_time)
            

#conting the number of accuracy of an IP
counting_ip = Counter(ips)

#printing suspicious IPs
print("\nSuspicious SSH Brute Force Detection")
pbf = False #possible brute force
for ip_add, nb_of_attempt in counting_ip.items():
    if nb_of_attempt >= 3: #if attempts are >= 3, considereing it as suspicious
        pbf = True
        if nb_of_attempt >= 5: #if attempts is >= 5, assigning to a High Severity
            sev = "HIGH" #severity of the threat
            total_high += 1
        else:
            sev = "MEDIUM" #if attempts is >=3 but 5, assigning to a Medium Severity
            total_medium += 1
        if ip_times[ip_add]: 
            first_attempt = ip_times[ip_add][0] # Getting the first attempt time if available from ip_add list
        else: 
            first_attempt = "Unknown"
        if ip_times[ip_add]: 
            last_attempt = ip_times[ip_add][-1] # Getting the last attempt time if available from ip_add list
        else:
            last_attempt = "Unknown"    
        # Printing detailed suspicious activity report
        print(f"Suspicious IP: {ip_add} - Number of attempts: {nb_of_attempt} - Severity: {sev} - First attempt: {first_attempt} - Last attempt: {last_attempt}")
if not pbf: # If no suspicious activity detected
    print("There hasn't been any suspicious SSH brute-force activity detected.")
 
total_attempts = total_high + total_medium
print("")
print(f"Total Number of Suspicious IPs: {total_attempts}")
print(f"Total Number of High Severity IPs: {total_high}")
print(f"Total Number of Medium Severity IPs: {total_medium}")