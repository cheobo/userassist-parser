from struct import unpack
import codecs
from datetime import datetime, timezone
import winreg
import csv
import re
import os
from regipy.registry import RegistryHive, RegistryKeyNotFoundException

# Function to store the known GUIDs in a variable
# the mapped GUIDs will be used to replace it with common names in Windows systems
# Example: GUID of 0139D44E-6AFE-49F2-8690-3DAFCAE6FFB8 will be replaced to CommonPrograms 
def map_known_GUID(file_path):
    guid_map = {}
    with open(file_path, mode='r') as infile:
        reader = csv.reader(infile)
        next(reader)  # Skip header row
        for rows in reader:
            guid, equivalent = rows
            guid_map[guid] = equivalent
    return guid_map

# Function to replace the GUID used in values (program's name/path) under Count key in UserAssist Registry for better readability
# Example: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\mspaint.exe -> {System}\mspaint.exe
def replace_guid(decrypted_value_name, guid_map):
    pattern = r"\{[0-9A-Fa-f\-]{36}\}"
    match = re.search(pattern, decrypted_value_name)
    if match:
        guid = match.group(0).replace("{", "").replace("}", "")
        equivalent = "{" + guid_map.get(guid, f"Unknown GUID: {guid}") + "}"
        return decrypted_value_name.replace(match.group(0), equivalent)
    return decrypted_value_name


# Function to decode ROT13 encoded program names
def decode_rot13(encoded_name):
    return codecs.decode(encoded_name, 'rot_13')


# Function to convert Windows timestamp to human-readable format and in UTC time format
def convert_windate(windate, program_name):
    if windate != 0:
        if program_name == 'UEME_CTLSESSION':
            return ""
        unix_epoch = (windate / 10000000) - 11644473600
        return datetime.fromtimestamp(unix_epoch, timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    return ""

# Function to convert Focus Time data (in milliseconds) to d(days), h(hours), m(minutes), s(seconds))
def convert_milliseconds(ms):
    # Calculate total seconds
    total_seconds = ms // 1000

    # Calculate days
    days = total_seconds // (24 * 3600)
    total_seconds = total_seconds % (24 * 3600)

    # Calculate hours
    hours = total_seconds // 3600
    total_seconds %= 3600

    # Calculate minutes
    minutes = total_seconds // 60

    # Calculate seconds
    seconds = total_seconds % 60

    return f"{days}d, {hours}h, {minutes}m, {seconds}s"


# Function to export parsed data to csv file
def write_to_csv(data, file_path):
    fieldnames = ["Program Name", "Run Counter", "Focus Count", "Focus Time", "Last Executed"]

    default_directory = ".\\outputs\\"
    default_directory = ".\\outputs\\"
    if not os.path.exists(default_directory):
        os.makedirs(default_directory)
        
    with open(default_directory + file_path, mode='w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for entry in data:
            writer.writerow(entry)
    print(f"UserAssist data successfully written to {file_path}")

# Function to parse UserAssist information from an online registry
def parse_userassist_live(guid_map, output_csv=None, print_to_cmd=False):
    parsed_data = []
    # Registry path for UserAssist keys
    userassist_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

    # Open the current user's registry key
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, userassist_path) as reg_key:
        try:
            index = 0
            while True:
                # Enumerate each subkey (GUID) under UserAssist
                guid = winreg.EnumKey(reg_key, index)
                guid_path = userassist_path + "\\" + guid
                # Open the subkey under UserAssist
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, guid_path) as guid:
                    try:
                        count_index = 0
                        while True:
                            # Open the Count subkey
                            count_subkey = winreg.EnumKey(guid, count_index)
                            count_path = guid_path + "\\" + count_subkey
                            # Open the values (program records) under the Count subkey
                            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, count_path) as program_key:
                                try:
                                    program_index = 0
                                    while True:
                                        # Loop through each value entries under the Count subkey
                                        value_name, value_data, value_type = winreg.EnumValue(program_key, program_index)
                                        
                                        # Read each value (Program Name and Data)
                                        decrypted_value_name = decode_rot13(value_name) # Decode program names using ROT-13 algorithm
                                        program_name = replace_guid(decrypted_value_name, guid_map) # Replace the GUID under Program Names (Ex: {1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}/mspaint.exe)

                                        # Set default values
                                        run_counter = 0
                                        focus_count = 0
                                        focus_time = "0d, 0h, 0m, 0s"
                                        last_executed = ""

                                        if program_name != 'UEME_CTLSESSION': # UEME_CTLSESSION is excluded because it contains the record for SESSION ID's not programs executed, which means different binary structure 
                                            # Parse the binary data to extract run counter, focus count, focus time, and last executed time
                                            run_counter = unpack('I', value_data[4:8])[0]
                                            focus_count = unpack('I', value_data[8:12])[0]
                                            focus_time_milliseconds = unpack('I', value_data[12:16])[0]
                                            focus_time = convert_milliseconds(focus_time_milliseconds)
                                            last_executed_timestamp = unpack('Q', value_data[60:68])[0]
                                            last_executed = convert_windate(last_executed_timestamp, program_name)

                                            parsed_data.append({
                                                "Program Name": program_name,
                                                "Run Counter": run_counter,
                                                "Focus Count": focus_count,
                                                "Focus Time": focus_time,
                                                "Last Executed": last_executed
                                            })

                                        if print_to_cmd:
                                            print("")
                                            print("--------------------------------------")
                                            print(f"Program Name: {program_name}")
                                            print(f"Run Counter: {run_counter}")
                                            print(f"Focus Count: {focus_count}")
                                            print(f"Focus Time: {focus_time}")
                                            print(f"Last Executed: {last_executed}")
                                            print("--------------------------------------")
                                            print("")
                                        program_index += 1
                                except OSError:
                                    pass
                            count_index += 1
                    except OSError:
                        pass
                index += 1
        except OSError:
            pass

    default_file_path = output_csv if output_csv else "live_parsed_userassist.csv"
    write_to_csv(parsed_data, default_file_path)

    return parsed_data


# Function to parse UserAssist information from an offline registry
def parse_userassist_offline(guid_map, ntuser_path, output_csv=None, print_to_cmd=False):
    parsed_data = []
    
    # Open the offline registry hive
    hive = RegistryHive(ntuser_path)
    userassist_path = r"\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist"

    try:
        # Access the UserAssist key
        userassist_key = hive.get_key(userassist_path)
        for subkey in userassist_key.iter_subkeys():
            # Loop through each subkey (GUIDs) under UserAssist 
            try:
                # Access the Count subkey
                count_subkey = subkey.get_subkey('Count')
                for value in count_subkey.iter_values():
                    # Loop through each value entries under the Count subkey
                    value_name = value.name
                    value_data = value.value
                    value_data = bytes.fromhex(value_data)

                    # Decode ROT13 encoded value name
                    decrypted_value_name = decode_rot13(value_name)
                    program_name = replace_guid(decrypted_value_name, guid_map)

                    # Set default values
                    run_counter = 0
                    focus_count = 0
                    focus_time = "0d, 0h, 0m, 0s"
                    last_executed = ""


                    if program_name != 'UEME_CTLSESSION':# UEME_CTLSESSION is excluded because it contains the record for SESSION ID's not programs executed, which means different binary structure 
                        # Parse the binary data to extract run counter, focus count, focus time, and last executed time
                        run_counter = unpack('I', value_data[4:8])[0]
                        focus_count = unpack('I', value_data[8:12])[0]
                        focus_time_milliseconds = unpack('I', value_data[12:16])[0]
                        focus_time = convert_milliseconds(focus_time_milliseconds)
                        last_executed_timestamp = unpack('Q', value_data[60:68])[0]
                        last_executed = convert_windate(last_executed_timestamp, program_name)

                        parsed_data.append({
                            "Program Name": program_name,
                            "Run Counter": run_counter,
                            "Focus Count": focus_count,
                            "Focus Time": focus_time,
                            "Last Executed": last_executed
                        })

                    if print_to_cmd:
                        print("")
                        print("--------------------------------------")
                        print(f"Program Name: {program_name}")
                        print(f"Run Counter: {run_counter}")
                        print(f"Focus Count: {focus_count}")
                        print(f"Focus Time: {focus_time}")
                        print(f"Last Executed: {last_executed}")
                        print("--------------------------------------")
                        print("")
            except RegistryKeyNotFoundException:
                pass

    except RegistryKeyNotFoundException:
        print(f"UserAssist path '{userassist_path}' not found in the registry hive.")

    default_file_path = output_csv if output_csv else "offline_parsed_userassist.csv"
    write_to_csv(parsed_data, default_file_path)

    return parsed_data