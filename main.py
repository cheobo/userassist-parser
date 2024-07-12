from userassist_parser import parse_userassist_live, parse_userassist_offline, map_known_GUID
import argparse
import csv
import pkg_resources

def main():

    parser = argparse.ArgumentParser(description="UserAssist Parser for Windows Systems (7/8/10/11)")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--live", action="store_true", help="Parse data from the live registry")
    group.add_argument("--offline", type=str, metavar="FILE", help="Parse data from an offline NTUSER.dat file")
    parser.add_argument("--output-csv", type=str, metavar="FILE", help="Save parsed data to CSV file")
    parser.add_argument("--show-output", action="store_true", dest="print_to_cmd", help="Print output to command line")

    args = parser.parse_args()

    # Load the csv file of known GUIDs in Windows systems
    csv_file_path = pkg_resources.resource_filename(__name__, 'lib/knownGUIDs.csv')
    GUID_map = map_known_GUID(csv_file_path)
    print("Parsing UserAssist keys...\n")

    if args.offline:
        parse_userassist_offline(GUID_map, args.offline, output_csv=args.output_csv, print_to_cmd=args.print_to_cmd)
    elif args.live:
        parse_userassist_live(GUID_map, output_csv=args.output_csv, print_to_cmd=args.print_to_cmd)

    if args.output_csv:
        print(f"UserAssist data written to '{args.output_csv}'.")
    else:
        print("UserAssist data written to default output file.")


if __name__ == "__main__":
    main()
