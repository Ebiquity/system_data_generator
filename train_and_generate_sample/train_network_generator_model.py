from ctgan import CTGANSynthesizer
import configparser
import ast
import os
import logging


class NetworkGeneratorModel:
    def __init__(self, data):
        self.data = data

        config = configparser.ConfigParser()
        config.read("attributes.ini")
        self.discrete_attributes = ast.literal_eval(config.get("ATTRIBUTES", "discrete_network_attributes"))
        print(self.discrete_attributes)

        if len(self.discrete_attributes) == 0:
            logging.warning("No Discrete Attribute defined")

    def train_and_save_ctgan(self, trained_generator_path=None, epochs=100):
        ctgan = CTGANSynthesizer(epochs=epochs)
        ctgan.fit(train_data=self.data, discrete_columns=self.discrete_attributes)
        logging.info("CTGAN model successfully trained")

        try:
            if trained_generator_path:
                ctgan.save(trained_generator_path)
            else:
                if not os.path.exists("../trained_generator"):
                    os.mkdir("../trained_generator")
                ctgan.save("trained_generator/trained_generator.pth")

            logging.info("Generator model successfully saved")
        except:
            logging.error("Generator model could not be saved")

        return ctgan
