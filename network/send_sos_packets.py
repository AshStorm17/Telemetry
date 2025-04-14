import argparse

def main(CC_Name):
    dir_name = CC_Name+"_tcp_payload"
    sos_lines = open(CC_Name+"_tcp_payload.txt", "r").readlines()
    for i in range(0,len(sos_lines),4):
        with open(dir_name+"/"+dir_name+"_"+str(i//4+1)+".txt", "w") as f:
            f.writelines(sos_lines[i:i+4])

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parses the single payload into multiple payloads")
    parser.add_argument("CC_Name", type=str, help="The name of the Control Center.")
    args = parser.parse_args()

    CC_Name = args.CC_Name
    main(CC_Name)