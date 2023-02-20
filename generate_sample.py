from ctgan import CTGANSynthesizer
import random

def get_next_event(event):
    if event == "DNS Query":
        return ["DNS Response", "ICMP Redirect", "ICMP TTL"]
    elif event == "DNS Response":
        return ["TCP SYN", "ICMP Redirect", "ICMP TTL"]
    elif event == "ICMP Redirect":
        return ["ICMP TTL"]
    elif event == "ICMP TTL":
        return ["ICMP Redirect"]
    elif event == "TCP CAM ACK":
        return ["TCP CAM Duplicate ACK", "TLS Client Hello"]
    elif event == "TCP CAM Duplicate ACK":
        return ["TCP Retransmission"]
    elif event == "TCP CAM PSH ACK":
        return ["TCP PSH Retransmission", "TCP PSH Window Full Retransmission"]
    elif event == "TCP DOM ACK":
        return ["TCP DOM Duplicate ACK"]
    elif event == "TCP DOM PSH ACK":
        return ["TCP PSH Retransmission"]
    elif event == "TCP FIN":
        return ["TCP RST"]
    elif event == "TCP SYN":
        return ["TCP SYN ACK"]
    elif event == "TCP SYN ACK":
        return ["TCP CAM ACK", "TCP DOM ACK", "TCP DOM PSH ACK"]
    elif event == "TLS Application Data":
        return ["TLS Application Data", "TLS Encrypted Alert", "TLS Uncaptured", "TLS Window_full", "TLS Retransmit",
                "TCP CAM ACK", "TCP DOM ACK", "TCP DOM PSH ACK"]
    elif event == "TLS Certificate":
        return ["TLS Server Key Exchange", "TLS Retransmit"]
    elif event == "TLS Change Cipher Spec":
        return ["TLS Encrypted Handshake Message"]
    elif event == "TLS Client Hello":
        return ["TLS Server Hello", "TLS Retransmit"]
    elif event == "TLS Client Key Exchange":
        return ["TLS Change Cipher Spec"]
    elif event == "TLS Encrypted Alert":
        return ["TCP FIN"]
    elif event == "TLS Encrypted Handshake Message":
        return ["TLS Application Data"]
    elif event == "TLS Server Hello":
        return ["TLS Certificate", "TLS Retransmit"]
    elif event == "TLS Server Hello Done":
        return ["TLS Client Key Exchange"]
    elif event == "TLS Server Key Exchange":
        return ["TLS Server Hello Done"]
    else:
        return []

def get_starting_Event():
    return "DNS Query"

class Generator:
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
            if current_event == "TCP RST":
                print("Current Event:: " + current_event)
                df2 = self.sample_event(current_event)

                df = df.append(df2)
                break
            else:
                if not df is None:
                    print("Current Event:: " + current_event)
                    if current_event == "TLS Client Hello":
                        client_hello_done = True

                    df2 = self.sample_event(current_event)
                    df = df.append(df2)
                else:
                    df = self.sample_event(current_event)

                if current_event in event_in_queue:
                    event_in_queue.remove(current_event)

                if client_hello_done:
                    if "TLS Client Hello" in event_in_queue:
                        event_in_queue.remove("TLS Client Hello")
                        event_in_queue.add("TLS Application Data")

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