import json
import stix2
import os 
import typing
from collections import defaultdict


def collect_annotations(annotations: typing.List[str]):
    objects, relations = [], []

    for line in annotations: 
        line_split = line.strip().split("\t")

        id = line_split[0]

        if id.startswith("T"):
            label = line_split[1].split(" ")[0]
            text = line_split[2]
            objects.append((id, label, text))

        elif id.startswith("R"):
            line_split = line_split[1].split(" ")

            from_id, to_id, rel = line_split[1].split(":")[1], line_split[2].split(":")[1], line_split[0]                      
            relations.append((from_id, to_id, rel))

    return objects, relations


indicator_annotations = dict()

for indicator_annotation_file in os.listdir("./IndicatorsLabeled"):
    with open(f"./IndicatorsLabeled/{indicator_annotation_file}", "r", encoding="utf-8") as fp: 
        indicator_annotations[indicator_annotation_file.split(".")[0]] = json.load(fp)


def get_indicator_label(indicator: str):
    for key, value in indicator_annotations.items():
        if indicator in value:
            return key
    return None


def deduplicateSDO(stix_sdos: dict, sdo, entity_target_key: str, sdo_type):
    for _, existing_sdo in stix_sdos.items():
        if isinstance(existing_sdo, sdo_type):
            if existing_sdo[entity_target_key] == sdo[entity_target_key]:
                return existing_sdo
        else:
            # type not existent -> return created sdo
            continue
    return sdo


def dataset_objects_to_SDOs(dataset_objects):
    SDOs_by_dataset_obj_id = dict()

    ignored_object_ids = []

    for object_id, label, text in dataset_objects: 
        sdo = None

        if label == "Malware":
            sdo = stix2.Malware(name=text, is_family=False)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Malware)
        
        elif label == "AttackPattern":
            sdo = stix2.AttackPattern(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.AttackPattern)
        
        elif label == "Vulnerability":
            sdo = stix2.Vulnerability(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Vulnerability)

        elif label == "ThreatActor":
            sdo = stix2.ThreatActor(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.ThreatActor)

        elif label == "Location":
            sdo = stix2.Location(region=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "region", stix2.Location)

        elif label == "Organization":
            sdo = stix2.Identity(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Identity)

        elif label == "OS":
            sdo = stix2.Software(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Software)

        elif label == "Application":
            sdo = stix2.Software(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Software)
        
        elif label == "MalwareType":
            ignored_object_ids.append(object_id)
            continue

        elif label == "Person":
            sdo = stix2.Identity(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Identity)
        
        elif label == "Indicator":
            indicator_label = get_indicator_label(text)
            if indicator_label == None:
                ignored_object_ids.append(object_id)
                continue
            
            elif indicator_label == "domain":
                sdo = stix2.Indicator(pattern=f"[domain-name:value = '{text}']", pattern_type="stix")

            elif indicator_label == "filename":
                sdo = stix2.Indicator(pattern=f"[file:name = '{text}']", pattern_type="stix")

            elif indicator_label == "filepath":
                sdo = stix2.Indicator(pattern=f"[file:path = '{text}']", pattern_type="stix")
            
            elif indicator_label == "ipv4":
                sdo = stix2.Indicator(pattern=f"[ipv4-addr:value = '{text}']", pattern_type="stix")

            elif indicator_label == "sha256":
                sdo = stix2.Indicator(pattern=f"[file:hashes.'SHA-256' = '{text}']", pattern_type="stix")

            elif indicator_label == "url":
                sdo = stix2.Indicator(pattern=f"[url:value = '{text}']", pattern_type="stix")

            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "pattern", stix2.Indicator)
            
        elif label == "Version":
            ignored_object_ids.append(object_id)
            continue

        elif label == "Time":
            ignored_object_ids.append(object_id)
            continue

        elif label == "Hardware":
            sdo = stix2.Infrastructure(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Infrastructure)

        SDOs_by_dataset_obj_id[object_id] = sdo 
    return SDOs_by_dataset_obj_id, ignored_object_ids



object_labels = set()

for file_name in os.listdir("../LADDER-Dataset"):
    if not file_name.endswith(".ann"):
        continue
    
    with open(f"../LADDER-Dataset/{file_name}", "r", encoding="utf-8") as fp: 
        annotations = fp.readlines()

    # 
    objects, relations = collect_annotations(annotations)

    for obj_id, label, text in objects:
        object_labels.add(label)


    SDOs_by_dataset_obj_id, ignored_object_ids = dataset_objects_to_SDOs(objects)


    bundle = []
    added_relations_by_from_id = defaultdict(list)


    for dataset_obj_id, sdo in SDOs_by_dataset_obj_id.items():
        for from_id, to_id, rel in relations:

            if from_id != dataset_obj_id:
                continue
            
            from_sdo = sdo 
            
            if to_id in ignored_object_ids:    
                continue

            to_sdo = SDOs_by_dataset_obj_id[to_id]

            if to_sdo.id not in added_relations_by_from_id[from_sdo.id]:
                relation = stix2.Relationship(source_ref=from_sdo.id, target_ref=to_sdo.id, relationship_type=rel)
                bundle.append(relation)

            added_relations_by_from_id[from_sdo.id].append(to_sdo.id)

            bundle.append(from_sdo)
            bundle.append(to_sdo)
            

    stix_bundle = stix2.Bundle(bundle)
    

    with open(f"../LADDER-Dataset/{file_name.split('.')[0]}.json", "w", encoding="utf-8") as fp:
        stix_bundle.fp_serialize(fp)
    
