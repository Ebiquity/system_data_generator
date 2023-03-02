from ctgan import CTGANSynthesizer

def get_memory_usage_limit():
    return 100

class CPUUsageGenerator:
    def __init__(self, generator_model_path):
        self.generator_model = CTGANSynthesizer().load(generator_model_path)


    def generate_cpu_usage_data(self, data_path):
        cpu_total = 0
        mem_total = 0
        counter = 0

        while cpu_total < get_memory_usage_limit() and mem_total < get_memory_usage_limit() and counter < 100:
            sample = self.generator_model.sample(n=1)

            if counter == 0:
                df = sample
            else:
                df = df.append(sample)

            cpu_total += float(sample["CPU"])
            mem_total += float(sample["MEM"])
            counter += 1

        df.to_csv(data_path, index=False)