import pandas as pd
import re

GATEWAY_IP = "192.168.1.1"
CAMERA_IP = "192.168.1.122"
COMPUTER_IP = "192.168.1.156"
DOMAIN_IP = "3.219.52.34"

CAM_PORT = 63542
DOM_PORT = 443

global start_time


def get_time(row):
    global start_time
    time = round(1000 * (row["Time"] - start_time), 2)
    start_time = row["Time"]

    return time


def transform_IP(row, col):
    if row[col] == GATEWAY_IP:
        return "GATEWAY_IP"
    elif row[col] == CAMERA_IP:
        return "CAMERA_IP"
    elif row[col] == COMPUTER_IP:
        return "COMPUTER_IP"
    elif row[col] == DOMAIN_IP:
        return "DOMAIN_IP"

def transform_port(row, col):
    print(row[col])
    print(type(row[col]))

    if row[col] == CAM_PORT:
        return "CAM_PORT"
    elif row[col] == DOM_PORT:
        return "DOM_PORT"
    else:
        return row[col]

def get_extra(row):
    if not pd.isnull(row["Extra"]):
        sub_info = row["Extra"].split(" ")
        row_info = {}
        for info in sub_info:
            info_s = info.split("=")
            if info_s[0] == "Seq":
                row_info["Seq"] = info_s[1]
            elif info_s[0] == "Ack":
                row_info["Ack"] = info_s[1]
            elif info_s[0] == "Win":
                row_info["Win"] = info_s[1]
            elif info_s[0] == "Len":
                row_info["Len"] = info_s[1]
            elif info_s[0] == "MSS":
                row_info["MSS"] = info_s[1]

        return row_info
    else:
        return None

def remove_sequence(row):
    s = row["Info"]
    if s.startswith("[TCP Dup ACK"):
        s = re.sub('#.+?]', ']', row["Info"])

    return s

def get_info(row):
    if row["Protocol"] == "DNS":
        if row["Info"].startswith("Standard query response"):
            return "DNS Response"
        elif row["Info"].startswith("Standard query"):
            return "DNS Query"
    elif row["Protocol"] == "ICMP":
        if row["Info"] == "Redirect             (Redirect for host)":
            return "ICMP Redirect"
        elif row["Info"] == "Time-to-live exceeded (Time to live exceeded in transit)":
            return "ICMP TTL"
    elif row["Protocol"] == "TLSv1.2":
        if row["Info"].startswith("[TCP Fast Retransmission]"):
            return "TLS Retransmit"
        elif row["Info"].startswith("[TCP Window Full]"):
            return "TLS Window_full"
        elif row["Info"].startswith("[TCP Previous segment not captured]"):
            return "TLS Uncaptured"
        else:
            return "TLS " + str(row["Info"])
    elif row["Protocol"] == "TCP":
        if "[SYN]" in row["Info"]:
            return "TCP SYN"
        elif "[SYN, ACK]" in row["Info"]:
            return "TCP SYN ACK"
        elif "[ACK]" in row["Info"] and row["Info"].startswith("63542  >  443"):
            return "TCP CAM ACK"
        elif "[ACK]" in row["Info"] and row["Info"].startswith("443  >  63542"):
            return "TCP DOM ACK"
        elif "[FIN, ACK]" in row["Info"]:
            return "TCP FIN"
        elif "[RST]" in row["Info"]:
            return "TCP RST"
        elif row["Info"] == "[TCP Retransmission] 63542  >  443 [PSH, ACK] ":
            return "TCP CAM PSH ACK"
        elif row["Info"] == "[TCP Retransmission] 443  >  63542 [PSH, ACK] ":
            return "TCP DOM PSH ACK"
        elif row["Info"].startswith("[TCP Out-Of-Order]"):
            return "TCP Out-Of-Order"
        elif row["Info"].startswith("[TCP Retransmission]"):
            return "TCP Retransmission"
        elif row["Info"].startswith("[TCP Spurious Retransmission]"):
            return "TCP PSH Retransmission"
        elif row["Info"].startswith("[TCP Window Full] [TCP Retransmission]"):
            return "TCP PSH Window FUll Retransmission"
        elif row["Info"].startswith("[TCP Window Update]"):
            return "TCP Window Update"
        elif row["Info"].startswith("[TCP Previous segment not captured]"):
            return "TCP Uncaptured"
        elif row["Info"].startswith("[TCP Dup ACK"):
            if "63542  >  443" in row["Info"]:
                return "TCP CAM Duplicate ACK"
            else:
                return "TCP DOM Duplicate ACK"
        else:
            return "TCP unseen segment"


def pre_process_network_traffic_data():
    df = pd.read_csv("./data/network_traffic_data.csv")
    cols = ["Source", "Source Port", "Destination", "Destination Port", "Protocol", "Length", "Info", "Extra"]
    print(df.shape)

    global start_time
    start_time = df['Time'].iloc[0].astype(float)

    df[cols] = df[cols].fillna('NULL')
    df['Info'] = df.apply(lambda row: remove_sequence(row), axis=1)

    df['repeats'] = df.groupby(cols)['Info'].transform('size')
    cols += ["repeats"]
    df = df.drop_duplicates(subset=cols, keep='first').reset_index(drop=True)

    df['Time'] = df.apply(lambda row: get_time(row), axis=1)
    df['Source'] = df.apply(lambda row: transform_IP(row, "Source"), axis=1)
    df['Destination'] = df.apply(lambda row: transform_IP(row, "Destination"), axis=1)
    df['Source Port'] = df.apply(lambda row: transform_port(row, "Source Port"), axis=1)
    df['Destination Port'] = df.apply(lambda row: transform_port(row, "Destination Port"), axis=1)

    df['Event'] = df.apply(lambda row: get_info(row), axis=1)
    df['Seq'] = df.apply(lambda row: get_extra(row).get("Seq") if not pd.isnull(get_extra(row)) else 'NULL', axis=1)
    df['Ack'] = df.apply(lambda row: get_extra(row).get("Ack") if not pd.isnull(get_extra(row)) else 'NULL', axis=1)
    df['Win'] = df.apply(lambda row: get_extra(row).get("Win") if not pd.isnull(get_extra(row)) else 'NULL', axis=1)
    df['Len'] = df.apply(lambda row: get_extra(row).get("Len") if not pd.isnull(get_extra(row)) else 'NULL', axis=1)
    df['MSS'] = df.apply(lambda row: get_extra(row).get("MSS") if not pd.isnull(get_extra(row)) else 'NULL', axis=1)

    df = df.drop(['No.', 'Info', 'Extra'], axis=1)

    print(df.shape)
    # df['repeats'] = df.groupby(df["Info"].ne(df["Info"].shift()).cumsum())["Info"].transform('size')
    # cols = ["Source", "Source Port", "Destination", "Destination Port", "Protocol", "Length", "Info", "Extra

    df.to_csv("./data/processed_network_traffic_data.csv", index=False)
