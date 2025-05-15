import json
import stix2
import stix2.hashes
from collections import defaultdict


with open("../STIXnet-Dataset/Annotations.json", mode="r", encoding="utf-8") as fp:
    label_studio_export = json.load(fp)



def collect_annotations(annotations):
    objects, relations = [], []

    for obj in annotations: 
        obj_type = obj["type"]
        
        if obj_type == "labels":
            # This fails initially as there are 5 object with no label! - manual annotation needed for: "cLkh2E389L", "IEzv6HuyUK", "PPePXMwUyp", "rA4TOUUb2i", "Z6cRBq0G-z"
            label = obj["value"]["labels"][0]
            text = obj["value"]["text"]
            id = obj["id"]

            objects.append((id, label, text))

        elif obj_type == "relation":    
            direction = obj["direction"]
            rel = obj["labels"][0]

            # "regular" flow of the relation is right: from_id --> to_id - direction left from_id <-- to_id, or we just turn the direction right and change the ids to_id --> from_id - there are only two irregular / left relations in the dataset
            if direction == "right":
                from_id = obj["from_id"]
                to_id = obj["to_id"]

            elif direction == "left":
                from_id = obj["to_id"]
                to_id = obj["from_id"]

            relations.append((from_id, to_id, rel)) 

    return objects, relations


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
    ignored_object_ids = [] # error validation for relation building
    
    for object_id, label, text in dataset_objects:
        sdo = None
        if label == "ipv4-addr":
            sdo = stix2.IPv4Address(value=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "value", stix2.IPv4Address)

        elif label == "location":
            sdo = stix2.Location(region=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "region", stix2.Location)

        elif label == "tool":
            sdo = stix2.Tool(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Tool)

        elif label == "tactic":
            ignored_object_ids.append(object_id)
            continue
            
        elif label == "domain-name":
            sdo = stix2.DomainName(value=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "value", stix2.DomainName)

        elif label == "attack-pattern":
            sdo = stix2.AttackPattern(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.AttackPattern)
    
        elif label == "vulnerability":
            sdo = stix2.Vulnerability(name=text) 
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Vulnerability)

        elif label == "identity":
            sdo = stix2.Identity(name=text) 
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Identity)
        
        elif label == "url":
            sdo = stix2.URL(value=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "value", stix2.URL)

        elif label == "campaign":
            sdo = stix2.Campaign(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Campaign)

        elif label == "intrusion-set":
            sdo = stix2.IntrusionSet(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.IntrusionSet)

        elif label == "sha256s":
            sdo = stix2.Indicator(pattern=f"[file:hashes.'SHA-256' = '{text}']", pattern_type="stix")
            print(sdo)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "pattern", stix2.Indicator)

        elif label == "malware": 
            sdo = stix2.Malware(name=text, is_family=False)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.Malware)

        elif label == "threat-actor":
            sdo = stix2.ThreatActor(name=text)
            sdo = deduplicateSDO(SDOs_by_dataset_obj_id, sdo, "name", stix2.ThreatActor)

        elif label == "indicator":
            ignored_object_ids.append(object_id) # 3 nonsense values: certificate screenshot keylogger
            continue

        elif label == "file_paths":
            text = text.replace("\\", "/")
            sdo = stix2.Indicator(pattern=f"[file:path = '{text}']", pattern_type="stix")
                        
        SDOs_by_dataset_obj_id[object_id] = sdo
    
    return SDOs_by_dataset_obj_id, ignored_object_ids





for obj in label_studio_export: 
    file_name = obj["file_upload"].split("-")[1]
    annotations = obj["annotations"][0]["result"]

    objects, relations = collect_annotations(annotations)
    
    SDOs_by_dataset_obj_id, ignored_object_ids = dataset_objects_to_SDOs(objects)

    bundle = []
    added_relations_by_from_id = defaultdict(list)

    print(file_name)

    # 
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


    # with open(f"./bundles-tmp2/{file_name}.json", "w", encoding="utf-8") as fp:
        # stix_bundle.fp_serialize(fp, pretty=True)