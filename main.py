import pandas as pd
from preprocess_data.preprocess_network_data import pre_process_network_traffic_data
from train_and_generate_sample.train_network_generator_model import NetworkGeneratorModel
from train_and_generate_sample.train_cpu_usage_generator_model import CpuGeneratorModel
from train_and_generate_sample.generate_network_traffic_sample import NetworkDataGenerator
from train_and_generate_sample.generate_cpu_usage_sample import CPUUsageGenerator
from postprocess_data.postprocess_network_data import postprocess_network_traffic_data

GENERATE_NETWORK_TRAFFIC = False
GENERATE_MEMORY_ACTIVITY = True


if GENERATE_NETWORK_TRAFFIC:
    pre_process_network_traffic_data()

    df = pd.read_csv("./data/processed_network_traffic_data.csv")
    generator_model = NetworkGeneratorModel(df)
    generator_model.train_and_save_ctgan("./trained_generator/network_traffic_data_generator.pth")

    generator = NetworkDataGenerator("./trained_generator/network_traffic_data_generator.pth")
    generator.sample_network_traffic_data("./synthetic_data/network_traffic_data.csv")
    postprocess_network_traffic_data("./synthetic_data/network_traffic_data.csv",
                                     "./results/generated_network_traffic_data.csv")

if GENERATE_MEMORY_ACTIVITY:
    df = pd.read_csv("./data/memory_activity_data.csv")
    generator_model = CpuGeneratorModel(df)
    # generator_model.train_and_save_ctgan("./trained_generator/cpu_usage_data_generator.pth")

    generator = CPUUsageGenerator("./trained_generator/cpu_usage_data_generator.pth")
    generator.generate_cpu_usage_data("./synthetic_data/cpu_usage_data.csv")

