import typing
import hashlib
import numpy as np 
from scipy.optimize import linear_sum_assignment
from sentence_transformers import SentenceTransformer
from sklearn.metrics.pairwise import cosine_similarity




def stixnet_f1(true_positives, false_positives, false_negatives):
    """
    Based on calculation presented in "STIXnet: A Novel and Modular Solution for Extracting All STIX Objects in CTI Reports" by Francesco Marchiori et. al. - online available: https://arxiv.org/abs/2303.09999
    """

    if true_positives == 0 and false_positives == 0 and false_negatives == 0:
        return 1.0, 1.0, 1.0 # this is perfect match e.g. [] == []!

    precision = true_positives / (true_positives + false_positives) if (true_positives + false_positives) != 0 else 0
    recall = true_positives / (true_positives + false_negatives) if (true_positives + false_negatives) != 0 else 0
    f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) != 0 else 0
    return precision, recall, f1_score






# in-memory cache dictionary
embedding_cache = {}

def get_model_hash(model: SentenceTransformer) -> str:
    model_info = str(model.__dict__)
    return hashlib.sha256(model_info.encode('utf-8')).hexdigest()


def get_embedding_from_cache_or_model(sentence, model):
    model_hash = get_model_hash(model)
    
    cache_key = (sentence, model_hash)

    if cache_key in embedding_cache:
        return embedding_cache[cache_key]
    else:
        embedding = model.encode(sentence)
        embedding_cache[cache_key] = embedding
        return embedding



def semantic_match_greedy(pred_list, gold_list, model: SentenceTransformer, threshold=0.8):
    if pred_list == gold_list:
        return len(pred_list), 0, 0
    elif len(pred_list) == 0 or len(gold_list) == 0:
        return 0, len(pred_list), len(gold_list)

    pred_vecs = [get_embedding_from_cache_or_model(pred, model) for pred in pred_list]
    gold_vecs = [get_embedding_from_cache_or_model(gold, model) for gold in gold_list]
    
    similarity_matrix = cosine_similarity(pred_vecs, gold_vecs)

    matched_gold_idxs = set() 
    true_positives = 0

    while True:
        max_idx = np.unravel_index(np.argmax(similarity_matrix, axis=None), similarity_matrix.shape)
        pred_idx, gold_idx = max_idx
        max_sim = similarity_matrix[pred_idx, gold_idx]

        if max_sim < threshold:
            break  # no suitable match left

        true_positives += 1
        matched_gold_idxs.add(gold_idx)

        similarity_matrix[pred_idx, :] = -1 
        similarity_matrix[:, gold_idx] = -1

    false_positives = len(pred_list) - true_positives
    false_negatives = len(gold_list) - len(matched_gold_idxs)

    return true_positives, false_positives, false_negatives





def semantic_match_hungarian(pred_list, gold_list, model: SentenceTransformer, threshold):
    if pred_list == gold_list:
        return len(pred_list), 0, 0
    elif len(pred_list) == 0 or len(gold_list) == 0:
        return 0, len(pred_list), len(gold_list)


    pred_vecs = [get_embedding_from_cache_or_model(pred, model) for pred in pred_list]
    gold_vecs = [get_embedding_from_cache_or_model(gold, model) for gold in gold_list]
    
    similarity_matrix = cosine_similarity(pred_vecs, gold_vecs)
    
    cost_matrix = -similarity_matrix

    row_ind, col_ind = linear_sum_assignment(cost_matrix)

    true_positives = sum(1 for r, c in zip(row_ind, col_ind) if similarity_matrix[r, c] >= threshold)

    false_positives = len(pred_list) - true_positives
    false_negatives = len(gold_list) - true_positives

    return true_positives, false_positives, false_negatives