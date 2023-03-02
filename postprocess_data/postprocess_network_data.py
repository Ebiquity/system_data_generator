import pandas as pd
import random
from datetime import datetime

HOME_IP = "192.168.1."
DOMAIN_URL = "VS-cam.u038.immedia-semi.com"
DOMAIN_IP = ["52.207.61.118", "3.219.52.34", "54.164.231.176", "3.211.79.229"]

def get_starting_sequence_number():
    return random.randint(10000, 100000)

def get_home_ip():
    x = random.randint(2, 256)
    camera_ip = HOME_IP + str(x)

    y = x
    while y == x:
        y = random.randint(2, 256)

    computer_ip = HOME_IP + str(y)

    gateway_ip = HOME_IP + "1"

    return camera_ip, computer_ip, gateway_ip

def get_domain_ip():
    return random.choice(DOMAIN_IP)

def get_camera_port():
    CAM_TO_DOM_PORT = "63542"
    CAM_TO_GATEWAY_PORT = "54176"
    DOM_PORT = "443"
    GATEWAY_PORT = "53"

    return CAM_TO_DOM_PORT, CAM_TO_GATEWAY_PORT, DOM_PORT, GATEWAY_PORT

def adjust_port_and_ip(df):
    info = []
    last_TLS_command = ""

    cam_ack_seq = ""
    cam_ack_win = ""
    cam_ack_ack = ""
    cam_ack_len = ""

    dom_ack_seq = ""
    dom_ack_win = ""
    dom_ack_ack = ""
    dom_ack_len = ""

    for index, row in df.iterrows():
        info_str = ""
        if row["Event"] == "DNS_Query":
            row["Source"] = "CAMERA_IP"
            row["Source Port"] = "CAM_TO_GATEWAY_PORT"
            row["Destination"] = "GATEWAY_IP"
            row["Destination Port"] = "GATEWAY_PORT"
            row["Protocol"] = "DNS"

            info_str = "Standard query 0xbc55 A " + DOMAIN_URL
        elif row["Event"] == "DNS_Response":
            row["Source"] = "GATEWAY_IP"
            row["Source Port"] = "GATEWAY_PORT"
            row["Destination"] = "CAMERA_IP"
            row["Destination Port"] = "CAM_TO_GATEWAY_PORT"
            row["Protocol"] = "DNS"

            ips_str = ""
            for ip in DOMAIN_IP:
                ips_str += " A " + str(ip)
            info_str = "Standard query response 0xbc55 A " + DOMAIN_URL + ips_str
        elif row["Event"] == "ICMP_Redirect":
            row["Source"] = df.iloc[index-1]["Source"]
            row["Source Port"] = df.iloc[index-1]["Source Port"]
            row["Destination"] = df.iloc[index-1]["Destination"]
            row["Destination Port"] = df.iloc[index-1]["Destination Port"]
            row["Protocol"] = "ICMP"

            info_str = "Redirect             (Redirect for host)"
        elif row["Event"] == "ICMP_TTL": # do it last
            row["Source"] = "COMPUTER_IP"
            row["Source Port"] = "GATEWAY_PORT"
            row["Destination"] = "GATEWAY_IP"
            row["Destination Port"] = "CAM_TO_GATEWAY_PORT"
            row["Protocol"] = "ICMP"

            info_str = "Time-to-live exceeded (Time to live exceeded in transit)"
        elif row["Event"] == "TCP_SYN":
            row["Source"] = "CAMERA_IP"
            row["Source Port"] = "CAM_TO_DOM_PORT"
            row["Destination"] = "DOMAIN_IP"
            row["Destination Port"] = "DOM_PORT"
            row["Seq"] = 0
            row["Protocol"] = "TCP"

            info_str = "CAM_TO_DOM_PORT  >  DOM_PORT [SYN] ," + "Seq=" + str(row["Seq"]) \
                       + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"]) + " MSS=" + str(row["MSS"])
        elif row["Event"] == "TCP_SYN_ACK":
            row["Source"] = "DOMAIN_IP"
            row["Source Port"] = "DOM_PORT"
            row["Destination"] = "CAMERA_IP"
            row["Destination Port"] = "CAM_TO_DOM_PORT"
            row["Seq"] = 0
            row["ACK"] = 1
            row["Protocol"] = "TCP"

            info_str = "DOM_PORT  >  CAM_TO_DOM_PORT [SYN, ACK] ," + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) \
                       + " Len=" + str(row["Len"]) + " MSS=" + str(row["MSS"])
        elif row["Event"] == "TCP_FIN":
            row["Source"] = "DOMAIN_IP"
            row["Source Port"] = "DOM_PORT"
            row["Destination"] = "CAMERA_IP"
            row["Destination Port"] = "CAM_TO_DOM_PORT"
            row["Protocol"] = "TCP"

            info_str = "\"DOM_PORT  >  CAM_TO_DOM_PORT [FIN, ACK] \"" + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"] == "TCP_RST":
            row["Source"] = "DOMAIN_IP"
            row["Source Port"] = "DOM_PORT"
            row["Destination"] = "CAMERA_IP"
            row["Destination Port"] = "CAM_TO_DOM_PORT"
            row["Protocol"] = "TCP"

            info_str = "\"DOM_PORT  >  CAM_TO_DOM_PORT [RST] \"" + "Seq=" + str(row["Seq"]) \
                      + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"] == "TCP_CAM_ACK":
            row["Source"] = "CAMERA_IP"
            row["Source Port"] = "CAM_TO_DOM_PORT"
            row["Destination"] = "DOMAIN_IP"
            row["Destination Port"] = "DOM_PORT"
            row["Protocol"] = "TCP"

            cam_ack_seq = row["Seq"]
            cam_ack_ack = row["Ack"]
            cam_ack_win = row["Win"]
            cam_ack_len = row["Len"]
            info_str = "CAM_TO_DOM_PORT  >  DOM_PORT [ACK] ," + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"] == "TCP_CAM_Duplicate_ACK" or row["Event"] == "TCP_Window_Update":
            row["Source"] = "CAMERA_IP"
            row["Source Port"] = "CAM_TO_DOM_PORT"
            row["Destination"] = "DOMAIN_IP"
            row["Destination Port"] = "DOM_PORT"
            row["Seq"] = cam_ack_seq
            row["Ack"] = cam_ack_ack
            row["Win"] = cam_ack_win
            row["Len"] = cam_ack_len
            row["Protocol"] = "TCP"

            if row["Event"] == "TCP_CAM_Duplicate_ACK":
                info_str = "[TCP Dup ACK ACK_SEQ  # SEQ_NO] CAM_TO_DOM_PORT  >  DOM_PORT [ACK] ," + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
            elif row["Event"] == "TCP_Window_Update":
                info_str = "[TCP Window Update] CAM_TO_DOM_PORT  >  DOM_PORT [ACK] ," + "Seq=" + str(row["Seq"]) \
                           + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"] == "TCP_CAM_PSH_ACK" or row["Event"] == "TCP_Out_Of_Order" \
                or row["Event"] == "TCP_Retransmission" or row["Event"] == "TCP_PSH_Retransmission" \
                or row["Event"] == "TCP_PSH_Window_FUll_Retransmission":
            row["Source"] = "CAMERA_IP"
            row["Source Port"] = "CAM_TO_DOM_PORT"
            row["Destination"] = "DOMAIN_IP"
            row["Destination Port"] = "DOM_PORT"
            row["Seq"] = cam_ack_seq
            row["Ack"] = cam_ack_ack
            row["Win"] = cam_ack_win
            row["Protocol"] = "TCP"

            if row["Event"] == "TCP_CAM_PSH_ACK":
                info_str = "\"[TCP Retransmission] CAM_TO_DOM_PORT  >  DOM_PORT [PSH, ACK] \"," + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
            elif row["Event"] == "TCP_Out_Of_Order":
                info_str = "\"[TCP Out-Of-Order] CAM_TO_DOM_PORT  >  DOM_PORT [PSH, ACK] \"," + "Seq=" + str(row["Seq"]) \
                           + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
            elif row["Event"] == "TCP_Retransmission":
                info_str = "\"[TCP Retransmission] CAM_TO_DOM_PORT  >  DOM_PORT [PSH, ACK] \"," + "Seq=" + str(
                    row["Seq"]) + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
            elif row["Event"] == "TCP_PSH_Retransmission":
                info_str = "\"[TCP Spurious Retransmission] CAM_TO_DOM_PORT  >  DOM_PORT [PSH, ACK] \"," + "Seq=" \
                           + str(row["Seq"]) + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) \
                           + " Len=" + str(row["Len"])
            elif row["Event"] == "TCP_PSH_Window_FUll_Retransmission":
                info_str = "\"[TCP Window Full] [TCP Retransmission] CAM_TO_DOM_PORT  >  DOM_PORT [PSH, ACK] \"," \
                           + "Seq=" + str(row["Seq"]) \
                           + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"] == "TCP_DOM_ACK":
            row["Source"] = "DOMAIN_IP"
            row["Source Port"] = "DOM_PORT"
            row["Destination"] = "CAMERA_IP"
            row["Destination Port"] = "CAM_TO_DOM_PORT"
            dom_ack_seq = row["Seq"]
            dom_ack_ack = row["Ack"]
            dom_ack_win = row["Win"]
            dom_ack_len = row["Len"]
            row["Protocol"] = "TCP"

            info_str = "DOM_PORT  >  CAM_TO_DOM_PORT [ACK] ," + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"] == "TCP_DOM_Duplicate_ACK":
            row["Source"] = "DOMAIN_IP"
            row["Source Port"] = "DOM_PORT"
            row["Destination"] = "CAMERA_IP"
            row["Destination Port"] = "CAM_TO_DOM_PORT"
            row["Seq"] = dom_ack_seq
            row["Ack"] = dom_ack_ack
            row["Win"] = dom_ack_win
            row["Len"] = dom_ack_len
            row["Protocol"] = "TCP"

            info_str = "[TCP Dup ACK DOM_ACK_SEQ  # SEQ_NO] DOM_PORT  >  CAM_TO_DOM_PORT [ACK] ," + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"] == "TCP_DOM_PSH_ACK":
            row["Source"] = "DOMAIN_IP"
            row["Source Port"] = "DOM_PORT"
            row["Destination"] = "CAMERA_IP"
            row["Destination Port"] = "CAM_TO_DOM_PORT"
            row["Seq"] = dom_ack_seq
            row["Ack"] = dom_ack_ack
            row["Win"] = dom_ack_win
            row["Protocol"] = "TCP"

            info_str = "\"[TCP Retransmission] DOM_PORT  >  CAM_TO_DOM_PORT [PSH, ACK] \"" + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"] == "TCP_Uncaptured":
            row["Source"] = "DOMAIN_IP"
            row["Source Port"] = "DOM_PORT"
            row["Destination"] = "CAMERA_IP"
            row["Destination Port"] = "CAM_TO_DOM_PORT"
            row["Protocol"] = "TCP"

            info_str = "[TCP Previous segment not captured] DOM_PORT  >  CAM_TO_DOM_PORT [ACK] ," + "Seq=" + str(row["Seq"]) \
                       + " Ack=" + str(row["Ack"]) + " Win=" + str(row["Win"]) + " Len=" + str(row["Len"])
        elif row["Event"].startswith("TLS_"):
            row["Source"] = "CAMERA_IP"
            row["Source Port"] = "CAM_TO_DOM_PORT"
            row["Destination"] = "DOMAIN_IP"
            row["Destination Port"] = "DOM_PORT"
            row["Protocol"] = "TLSv1.2"

            if row["Event"] == "TLS_Retransmit":
                info_str = "\"[TCP Fast Retransmission] , " + last_TLS_command + "\""
            elif row["Event"] == "TLS_Window_full":
                info_str = "\"[TCP Window Full] , Application Data\""
            elif row["Event"] =="TLS_Uncaptured":
                info_str = "\"[TCP Previous segment not captured] , Application Data\""
            else:
                info_str = row["Event"].replace("TLS_", "")
                info_str = info_str.replace("_", " ")

                if row["Event"] == "TLS_Server_Hello" or row["Event"] == "TLS_Application_Data"\
                        or row["Event"] == "TLS_Client_Hello" or row["Event"] == "TLS_Certificate":
                    last_TLS_command = info_str
        else:
            print(row["Event"])

        df.iloc[index] = row
        info.append(info_str)

    df["Info"] = info

    return df

def replace_port_and_ip(df):
    camera_ip, computer_ip, gateway_ip = get_home_ip()
    domain_ip = get_domain_ip()

    CAM_TO_DOM_PORT, CAM_TO_GATEWAY_PORT, DOM_PORT, GATEWAY_PORT = get_camera_port()

    df.replace({'CAMERA_IP': camera_ip, 'COMPUTER_IP': computer_ip,
                'GATEWAY_IP': gateway_ip, 'DOMAIN_IP': domain_ip,
                'CAM_TO_DOM_PORT': CAM_TO_DOM_PORT, 'CAM_TO_GATEWAY_PORT': CAM_TO_GATEWAY_PORT,
                'DOM_PORT': DOM_PORT, 'GATEWAY_PORT': GATEWAY_PORT}, regex=True, inplace=True)

    return df

def update_time_and_number(df):
    start_time = random.uniform(1, 10)
    current_time = start_time

    starting_index = get_starting_sequence_number()
    sequence_numbers = []

    for index, row in df.iterrows():
        time = (row["Time"] * .01) + current_time
        row["Time"] = time
        current_time = row["Time"]

        sequence_number = starting_index + index

        sequence_numbers.append(sequence_number)

        df.iloc[index] = row

    df["No."] = sequence_numbers

    return df


def update_sequence_number(df):
    last_seen_ack_number = 0
    last_seen_dom_ack_number = 0

    ack_dup_counter = 0
    dom_ack_dup_counter = 0
    for index, row in df.iterrows():
        if row["Event"] == "TCP_CAM_ACK":
            last_seen_ack_number = row["No."]
            ack_dup_counter = 1
        elif row["Event"] == "TCP_DOM_ACK":
            last_seen_dom_ack_number = row["No."]
            dom_ack_dup_counter = 1
        elif row["Event"] == "TCP_CAM_Duplicate_ACK":
            row["Info"] = row["Info"].replace("ACK_SEQ", str(last_seen_ack_number))
            row["Info"] = row["Info"].replace("SEQ_NO", str(ack_dup_counter))
            ack_dup_counter += 1
        elif row["Event"] == "TCP_DOM_Duplicate_ACK":
            row["Info"] = row["Info"].replace("DOM_ACK_SEQ", str(last_seen_dom_ack_number))
            row["Info"] = row["Info"].replace("SEQ_NO", str(dom_ack_dup_counter))
            dom_ack_dup_counter += 1

        df.iloc[index] = row

    return df


def postprocess_network_traffic_data(data_path, results_path):
    df = pd.read_csv(data_path)

    df = adjust_port_and_ip(df)

    df = replace_port_and_ip(df)

    df = pd.DataFrame(df.values.repeat(df["repeats"], axis=0), columns=df.columns)

    df = update_time_and_number(df)

    df = update_sequence_number(df)

    df = df[['No.', 'Time', 'Source', 'Source Port', 'Destination', 'Destination Port', 'Protocol', 'Length', 'Info']]

    df.to_csv(results_path, index=False)
