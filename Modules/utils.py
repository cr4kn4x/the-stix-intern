import os 
import stix2
import typing
import dspy 
import random 
from collections import defaultdict
import re
import json
from pydantic import BaseModel, Field


def load_dataset_from_disk(base_path: str) -> typing.Dict[str, stix2.Bundle]:
    dataset: typing.Dict[str, stix2.Bundle] = dict()

    for file in os.listdir(base_path):
        id, extension = file.split(".")

        if extension != "json":
            continue

        stix = f"{id}.json"
        html = f"{id}.html"

        if os.path.exists(f"{base_path}/{stix}") and os.path.exists(f"{base_path}/{html}"):
            with open(f"{base_path}/{stix}", "r", encoding="utf-8") as fp:
                bundle = stix2.parse(fp)
                assert isinstance(bundle, stix2.Bundle)
                dataset[id] = {"stix_bundle": bundle, "html": None}

            with open(f"{base_path}/{html}", "r", encoding="utf-8") as fp:
                html_content = fp.read()
                dataset[id]["html"] = html_content
                
    return dataset


def get_dspy_examples(base_path: str, html_to_text_parser: dspy.Module) -> typing.List[dspy.Example]:
    examples = []
    for key, value in load_dataset_from_disk(base_path).items(): 

        threat_report = html_to_text_parser.forward(value["html"])

        example = dspy.Example(threat_report_html=value["html"], threat_report=threat_report, stix_bundle=value["stix_bundle"], id=key).with_inputs("threat_report_html", "threat_report")
    
        examples.append(example)
    return examples


def get_dspy_examples_randomized(base_path: str, html_to_text_parser: dspy.Module, random_seed: int = 1337) -> typing.List[dspy.Example]:
    random.seed(a=random_seed)

    dataset = get_dspy_examples(base_path, html_to_text_parser)
    random.shuffle(dataset)
    return dataset




def generate_malware_extraction_dataset(dataset: typing.List[dspy.Example]) -> typing.List[dspy.Example]:
    malware_extraction_dataset = []
    
    for example in dataset: 
        spec_example = dspy.Example(threat_report=example.threat_report, id=example.id, malware_names=list({obj.name for obj in get_objects_from_bundle(example.stix_bundle, stix2.Malware)})).with_inputs("threat_report")

        malware_extraction_dataset.append(spec_example)

    return malware_extraction_dataset


def generate_threat_actors_extraction_dataset(dataset: typing.List[dspy.Example]) -> typing.List[dspy.Example]:
    threat_actor_extraction_dataset = []
    
    for example in dataset: 
        spec_example = dspy.Example(threat_report=example.threat_report, id=example.id, threat_actors=list({obj.name for obj in get_objects_from_bundle(example.stix_bundle, stix2.ThreatActor)})).with_inputs("threat_report")

        threat_actor_extraction_dataset.append(spec_example)

    return threat_actor_extraction_dataset







def get_object_by_id(id: str, stix_bundle: stix2.Bundle):
    for item in stix_bundle["objects"]:
        if item["type"] == "relationship":
            continue
        elif item["id"] == id:
            return item
    return None


def generate_attack_patterns_used_by_malware_dataset(dataset: typing.List[dspy.Example]) -> typing.List[dspy.Example]:
    attack_patterns_dataset = []

    for example in dataset: 
        bundle = example.stix_bundle
    

        attack_patterns_used_by_malware = defaultdict(list)  
        # +++++++++++++++++++++++++++++++++++++++++++++++++
        for item in bundle["objects"]:
            type = item["type"]

            if type == "relationship":
                source_ref = item["source_ref"]
                target_ref = item["target_ref"] 
                relationship_type = item["relationship_type"]
                
                source_obj = get_object_by_id(source_ref, bundle)
                target_obj = get_object_by_id(target_ref, bundle)

                if relationship_type != "uses":
                    continue

                elif source_obj["type"] == "malware" and target_obj["type"] == "attack-pattern":
                    # <source_obj:malware> <uses> <target_obj:attack-pattern>
                    malware_name = source_obj["name"]
                    attack_pattern = target_obj["name"]

                    attack_patterns_used_by_malware[malware_name].append(attack_pattern)
        # +++++++++++++++++++++++++++++++++++++++++++++++++
        
        # +++++++++++++++++++++++++++++++++++++++++++++++++
        leftover_malwares = list({obj.name for obj in get_objects_from_bundle(bundle, stix2.Malware)})

        for malware, used_attack_patterns in attack_patterns_used_by_malware.items(): 
            leftover_malwares.remove(malware)

            spec_example = dspy.Example(
                threat_report=example.threat_report, 
                                    id=example.id, 
                                    malware=malware,
                                    attack_patterns_used_by_malware=used_attack_patterns,
                                    ).with_inputs("threat_report", "malware")
            # add to dataset
            attack_patterns_dataset.append(spec_example)
        # +++++++++++++++++++++++++++++++++++++++++++++++++

        for malware in leftover_malwares:
            spec_example = dspy.Example(
                threat_report=example.threat_report, 
                                    id=example.id, 
                                    malware=malware,
                                    attack_patterns_used_by_malware=[],
                                    ).with_inputs("threat_report", "malware")
            # add to dataset
            attack_patterns_dataset.append(spec_example)

    return attack_patterns_dataset
















def get_all_html_paths(base_path: str) -> typing.List[str]:
    paths: typing.List[str] = []
    
    for file in os.listdir(base_path):
        if file.split(".")[1] == "html":
            paths.append(file)
    
    return paths


def get_objects_from_bundle(bundle: stix2.Bundle, obj_type):
    res = []
    
    objects = bundle["objects"]
    for obj in objects:
        if isinstance(obj, obj_type):
            res.append(obj)
    return res


def split_dataset(split_at: int, dataset: typing.List):
    trainset, devset = dataset[:split_at], dataset[split_at:]
    print(len(trainset), len(devset), "total:", len(trainset)+len(devset), "train-ratio:", len(trainset)/len(dataset), "dev-ratio:", len(devset)/len(dataset))
    return trainset, devset




def generate_all_attack_patterns_dataset(dataset: typing.List[dspy.Example]) -> typing.List[dspy.Example]:
    attack_patterns_dataset = []

    class triple(BaseModel):
        """internal helper class"""
        source: str = Field(description="name of the SDO")
        source_type: typing.Literal["malware"]

        relationship: typing.Literal["uses"]

        target_attack_pattern: str
        target_type: typing.Literal["attack-pattern"]


    for example in dataset: 
        bundle = example.stix_bundle
    
        attack_patterns_used_by_malware = defaultdict(list)  
        # +++++++++++++++++++++++++++++++++++++++++++++++++
        for item in bundle["objects"]:
            type = item["type"]

            if type == "relationship":
                source_ref = item["source_ref"]
                target_ref = item["target_ref"]
                relationship_type = item["relationship_type"]
                
                source_obj = get_object_by_id(source_ref, bundle)
                target_obj = get_object_by_id(target_ref, bundle)

                if relationship_type != "uses":
                    continue

                elif source_obj["type"] == "malware" and target_obj["type"] == "attack-pattern":
                    # <source_obj:malware> <uses> <target_obj:attack-pattern>
                    malware_name = source_obj["name"]
                    attack_pattern = target_obj["name"]

                    attack_patterns_used_by_malware[malware_name].append(attack_pattern)
        # +++++++++++++++++++++++++++++++++++++++++++++++++
        attack_pattern_triples: typing.List[triple] = []
        for malware, attack_patterns in attack_patterns_used_by_malware.items(): 

            for attack_pattern in attack_patterns: 
                attack_pattern_triples.append(triple(source=malware, source_type="malware", relationship="uses", target_attack_pattern=attack_pattern, target_type="attack-pattern"))


        example = dspy.Example(
            threat_report=example.threat_report,
            id = example.id, 
            mentioned_malwares=list(set([malware["name"] for malware in get_objects_from_bundle(bundle, stix2.Malware)])),
            mentioned_threat_actors=list(set([threat_actor["name"] for threat_actor in get_objects_from_bundle(bundle, stix2.ThreatActor)])),
            attack_pattern_triples = attack_pattern_triples
        ).with_inputs("threat_report", "mentioned_malwares", "mentioned_threat_actors")

        attack_patterns_dataset.append(example)
        # +++++++++++++++++++++++++++++++++++++++++++++++++

    return attack_patterns_dataset




def generate_targets_dataset(dataset: typing.List[dspy.Example]) -> typing.List[dspy.Example]:
    targets_dataset = []


    class triple(BaseModel):
        """internal helper class"""
        source: str = Field(description="name of the SDO")
        source_type: typing.Literal["malware"]

        relationship: typing.Literal["targets"]

        target: str
        target_type: typing.Literal["software", "location"]
        


    for example in dataset:
        bundle = example.stix_bundle 

        targeted_softwares_by_malware = defaultdict(list)
        targeted_location_by_malware = defaultdict(list)

        # +++++++++++++++++++++++++++++++++++++++++++++++++
        for item in bundle["objects"]:
            type = item["type"]

            if type == "relationship":
                source_ref = item["source_ref"]
                target_ref = item["target_ref"]
                relationship_type = item["relationship_type"]
                
                source_obj = get_object_by_id(source_ref, bundle)
                target_obj = get_object_by_id(target_ref, bundle)

                if relationship_type != "targets":
                    continue

                if source_obj["type"] != "malware": 
                    continue

                malware_name = source_obj["name"]
                if target_obj["type"] == "location": 
                    location = target_obj["region"]
                    targeted_location_by_malware[malware_name].append(location)
                    
                elif target_obj["type"] == "software": 
                    software = target_obj["name"]
                    targeted_softwares_by_malware[malware_name].append(software)
                    
                else:
                    # irrelevant target type 
                    continue


        targets_triples: typing.List[triple] = []
        # 1. all targeted softwares
        for malware, software_targets in targeted_softwares_by_malware.items(): 
            for software_target in software_targets:
                targets_triples.append(triple(source=malware, source_type="malware", relationship="targets", target=software_target, target_type="software"))

        # 2. all targeted locations
        for malware, location_targets in targeted_location_by_malware.items(): 
            for location_target in location_targets:
                targets_triples.append(triple(source=malware, source_type="malware", relationship="targets", target=location_target, target_type="location"))
        

        # 3. create final example
        example = dspy.Example(
            threat_report=example.threat_report,
            id = example.id, 
            mentioned_malwares=list(set([malware["name"] for malware in get_objects_from_bundle(bundle, stix2.Malware)])),
            mentioned_threat_actors=list(set([threat_actor["name"] for threat_actor in get_objects_from_bundle(bundle, stix2.ThreatActor)])),
            targets_triples = targets_triples
        ).with_inputs("threat_report", "mentioned_malwares", "mentioned_threat_actors")

        targets_dataset.append(example)
        # +++++++++++++++++++++++++++++++++++++++++++++++++
    return targets_dataset






def calc_f1_micro(recall_values: typing.Iterable, precision_values: typing.Iterable, ndigits: int = None): 
    t = []
    for recall, precison in zip(recall_values, precision_values): 
        t.append( (2*recall*precison) / (recall+precison) if recall + precison > 0 else 0)

    f1 = sum(t) / len(t)

    if ndigits: 
        return round(f1, ndigits)
    return f1


def calc_avg(list: typing.Iterable, ndigits: int = None): 
    avg = sum(list) / len(list)
    if ndigits:
        return round(avg, ndigits)
    return avg


def convert_to_percentage(value, ndigits: int = None):
    if ndigits: 
        return round(value*100, ndigits)
    return value * 100



def calc_avg_percentage(list: typing.Iterable, ndigits: int = None): 
    t = calc_avg(list)
    return convert_to_percentage(t, ndigits)

def calc_f1_micro_percentage(recall_values: typing.Iterable, precision_values: typing.Iterable, ndigits: int = None): 
    t = calc_f1_micro(recall_values, precision_values)
    return convert_to_percentage(t, ndigits)



def load_json_files(base_path, categories, models):
    data = {}

    for model in models: 
        data[model] = dict() 

        data[model]["Baseline"] = dict()
        data[model]["ZERO-O1"] = dict()
        data[model]["ZERO-O2"] = dict() 
        data[model]["FS-O1"] = dict()
        data[model]["FS-O2"] = dict()

    for category in categories: 
        for model in models: 
            # f1
            file_path = os.path.join(base_path, category, f"{model}_f1.json")
            with open(file_path, "r") as fp:
                data[model][category]["f1"] = json.load(fp)

            # precision
            file_path = os.path.join(base_path, category, f"{model}_precision.json")
            with open(file_path, "r") as fp:
                data[model][category]["precision"] = json.load(fp)
            
            # precision
            file_path = os.path.join(base_path, category, f"{model}_recall.json")
            with open(file_path, "r") as fp:
                data[model][category]["recall"] = json.load(fp)
    
    return data