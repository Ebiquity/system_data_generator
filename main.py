import pandas as pd
from ctgan import CTGANSynthesizer
from preprocess_data import pre_process_network_traffic_data
from train_model import GeneratorModel
from generate_sample import Generator

GENERATE_NETWORK_TRAFFIC = True


if GENERATE_NETWORK_TRAFFIC:
    # pre_process_network_traffic_data()

    df = pd.read_csv("./data/processed_network_traffic_data.csv")
    # generator_model = GeneratorModel(df)
    # generator_model.train_and_save_ctgan("./trained_generator/network_traffic_data_generator.pth")

    generator = Generator("./trained_generator/network_traffic_data_generator.pth")
    generator.sample_network_traffic_data("./synthetic_data/network_traffic_data.csv")