import os

# get current script folder
current_dir = os.path.dirname(__file__)

# build file paths to ioc.txt and access.log
ioc_file_path = os.path.join(current_dir, "..", "ioc.txt")
access_log_path = os.path.join(current_dir, "..", "access.log")

# lists for suspicious IOCs (IPs and paths)
ioc_ips = []
ioc_paths = []

# read IOC file
with open(ioc_file_path, "r", encoding="utf-8", errors="ignore") as f: #opening the IOC file and classify each line as IP or Path
    for line in f: #reading the file line by line
        line = line.strip() #clear spaces at the beginning and at the end, and also go to line(\n)

        if not line: #if the line is empty, skipping it
            continue

        # classify as IP or path
        if line[0].isdigit(): #if the first character is a digit, consider it as IP
            ioc_ips.append(line) #add it to the known suspecious Ips list
        elif line.startswith("/"):
            ioc_paths.append(line) #add it to the know sensitiv path list
            

print("\n=== IOC Match Detection ===")

both_matched = 0 # Counting when both IP and path match
matched_ip_count = 0  # Counting when only IP matches
matched_path_count = 0  # Counting when only path matches

# read access log and check matches
with open(access_log_path, "r", encoding="utf-8", errors="ignore") as f:
    for line in f: #reading the file line by line
        line = line.strip() #clear spaces at the beginning and at the end, and also go to line(\n)
        
        #initialising variables for matches
        found_ip = None
        found_path = None
        
        for suspicious_ip in ioc_ips:
            if suspicious_ip in line:
               found_ip = suspicious_ip
               break
        for suspicious_path in ioc_paths:
            if suspicious_path in line:
               found_path = suspicious_path
               break
            
            
        if found_ip and found_path:
            print(f"High Alert, Suspicious IOC IP and Path: {found_ip} - {found_path}")
            print(f"Log entry: {line}\n")
            both_matched += 1
        elif found_ip:
            print(f"Medium Alert, Suspicious IOC IP detected: {found_ip}")
            print(f"Log entry: {line}\n")
            matched_ip_count += 1
        elif found_path:
            print(f"Medium Alert, Suspicious IOC path detected: {found_path}")
            print(f"Log entry: {line}\n")
            matched_path_count += 1
            
print(f"Total suspicious events: {both_matched + matched_ip_count + matched_path_count}")            
print(f"The total High Alert are: {both_matched}")
print(f"The total Medium Alert for IPs are: {matched_ip_count}")
print(f"The total Medium Alert for Paths are: {matched_path_count}") 