import json


def jsonParser(configFile):
    with open(configFile, "r") as read_file:
        developer = json.load(read_file)
        for key, certsDetails in developer.items():
            return certsDetails