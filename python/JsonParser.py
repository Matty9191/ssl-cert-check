import json


def json_parser(config_file):
    with open(config_file, "r") as read_file:
        developer = json.load(read_file)
        for key, certs_details in developer.items():
            return certs_details