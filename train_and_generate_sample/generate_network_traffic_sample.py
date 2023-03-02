from ctgan import CTGANSynthesizer
import random

def get_next_event(event):
    if event == "DNS_Query":
        return ["DNS_Response", "ICMP_Redirect", "ICMP_TTL"]
    elif event == "DNS_Response":
        return ["TCP_SYN"]
    elif event == "ICMP_Redirect":
        return ["ICMP_TTL"]
    elif event == "ICMP_TTL":
        return ["ICMP_Redirect"]
    elif event == "TCP_SYN":
        return ["TCP_SYN_ACK"]
    elif event == "TCP_SYN_ACK":
        return ["TCP_CAM_ACK", "TCP_DOM_ACK"]
    elif event == "TCP_FIN":
        return ["TCP_RST"]
    elif event == "TCP_CAM_ACK":
        return ["TCP_CAM_Duplicate_ACK", "TCP_Window_Update", "TCP_CAM_PSH_ACK", "TLS_Client_Hello"]
    elif event == "TCP CAM PSH ACK":
        return ["TCP_Out_Of_Order", "TCP_Retransmission", "TCP_PSH_Retransmission",
                "TCP_PSH_Window_FUll_Retransmission"]
    elif event == "TCP_DOM_ACK":
        return ["TCP_DOM_Duplicate_ACK", "TCP_DOM_PSH_ACK", "TCP_Uncaptured"]
    elif event == "TLS_Client_Hello":
        return ["TLS_Server_Hello", "TLS_Retransmit"]
    elif event == "TLS_Server_Hello":
        return ["TLS_Certificate", "TLS_Retransmit"]
    elif event == "TLS_Certificate":
        return ["TLS_Server_Key_Exchange", "TLS_Retransmit"]
    elif event == "TLS_Server_Key_Exchange":
        return ["TLS_Server_Hello_Done"]
    elif event == "TLS_Server_Hello_Done":
        return ["TLS_Client_Key_Exchange"]
    elif event == "TLS_Client_Key_Exchange":
        return ["TLS_Change_Cipher_Spec"]
    elif event == "TLS_Change_Cipher_Spec":
        return ["TLS_Encrypted_Handshake_Message"]
    elif event == "TLS_Encrypted_Handshake_Message":
        return ["TLS_Application_Data"]
    elif event == "TLS_Application_Data":
        return ["TLS_Application_Data", "TLS_Encrypted_Alert", "TLS_Uncaptured", "TLS_Window_full", "TLS_Retransmit",
                "TCP_CAM_ACK", "TCP_DOM_ACK"]
    elif event == "TLS_Encrypted_Alert":
        return ["TCP_FIN"]
    else:
        return []

def get_starting_Event():
    return "DNS_Query"

class NetworkDataGenerator:
    def __init__(self, generator_model_path):
        self.generator_model = CTGANSynthesizer().load(generator_model_path)

    def sample_event(self, event):
        mask = ""
        while not mask == event:
            df2 = self.generator_model.sample(n=1, condition_column="Event", condition_value=event)
            mask = df2["Event"][0]

        return df2

    def sample_network_traffic_data(self, data_path):
        current_event = get_starting_Event()
        event_in_queue = set()

        client_hello_done = False

        counter = 0
        df = None
        while counter < 1000:
            if current_event == "TCP_RST":
                print("Current Event:: " + current_event)
                df2 = self.sample_event(current_event)

                df = df.append(df2)
                break
            else:
                if not df is None:
                    print("Current Event:: " + current_event)
                    if current_event == "TLS_Client_Hello":
                        client_hello_done = True

                    df2 = self.sample_event(current_event)
                    df = df.append(df2)
                else:
                    df = self.sample_event(current_event)

                if current_event in event_in_queue:
                    event_in_queue.remove(current_event)

                if client_hello_done:
                    if "TLS_Client_Hello" in event_in_queue:
                        event_in_queue.remove("TLS_Client_Hello")
                        event_in_queue.add("TLS_Application_Data")

                next_events = get_next_event(current_event)

                if len(next_events) > 0:
                    for next_event in next_events:
                        event_in_queue.add(next_event)

                event_in_queue_list = list(event_in_queue)
                print(event_in_queue_list)

                if len(event_in_queue_list) > 0:
                    current_event = random.choice(event_in_queue_list)

                counter += 1

        df.to_csv(data_path, index=False)