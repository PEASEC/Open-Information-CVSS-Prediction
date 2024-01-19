# Main File for the CVSS Predictor

import os
import time
import math
import json
import datetime
import argparse
from datetime import datetime
from typing import List, Optional, Dict
import numpy as np
import torch
import pandas as pd
from sklearn.metrics import cohen_kappa_score
from datasets import Dataset, load_metric
from transformers.trainer_utils import speed_metrics
from transformers import AutoTokenizer, DistilBertTokenizerFast, Trainer, IntervalStrategy, AutoModelForSequenceClassification, TrainingArguments

from CustomEvalTrainer import CustomEvalTrainer


def main():
    print(f'CVSS Predictor started at {datetime.now().strftime("%d/%m/%y %H:%M:%S")}')
    parser = argparse.ArgumentParser(description='Train or evaluate a CVSS predictor model')
    parser.add_argument('action', type=str, choices=['train', 'eval'], help='The action that should be performed')
    parser.add_argument('--target', '-t', required=True, type=str, choices=['av', 'ac', 'pr', 'ui', 's', 'c', 'i', 'a'], metavar='value', help="The CVSSv3 Vector part on which the script should work.")
    parser.add_argument('--checkpoint_path', '-c', type=str, default='.', metavar='directory', help="Path to the directory in which checkpoints are kept")
    parser.add_argument('--model_checkpoint', '-mc', type=str, default='latest', metavar='name', help='The model that should be used. Use "latest" for the latest checkpoint in checkpoint_path or "base" for the untrained model')
    parser.add_argument('--eval_file', '-e', type=str, required=True, metavar='file_name', help='Path and name of the file in which the results of the evaluation should be stored')
    parser.add_argument('--dataset_path', '-d', type=str, required=True, metavar='path', help='Path to the directory which contains the train and test dataset')
    parser.add_argument('--epochs', '-ep', type=int, default=3, metavar='num', help='Number of Epochs to train')
    parser.add_argument('--base_model', '-bm', type=str, default='distilbert-base-uncased', metavar='name', help='Name of the base model')

    args = parser.parse_args()
    target_var = args.target
    checkpoint_path = args.checkpoint_path
    model_name = args.model_checkpoint
    eval_file_name = args.eval_file.replace(',', '')
    dataset_path = args.dataset_path
    number_of_epochs = args.epochs
    base_model = args.base_model

    batch_size = 16

    if not torch.cuda.is_available():
        print('No GPU detected')
        return
    else:
        n = torch.cuda.device_count()
        print(f'{n} GPU detected')
        gpu_info = str(torch.cuda.get_device_properties(0)).replace("_CudaDeviceProperties", "")
        print(f'Device {0}: "{gpu_info}"')
        if 'A100' in gpu_info:
            # 40Gb
            if base_model == 'distilbert-base-uncased':
                batch_size = 48
            elif base_model == 'prajjwal1/bert-small':
                batch_size = 128
            elif base_model == 'prajjwal1/bert-medium':
                batch_size = 56
        elif 'V100' in gpu_info:
            # 32Gb
            if base_model == 'distilbert-base-uncased':
                batch_size = 40
            elif base_model == 'prajjwal1/bert-small':
                batch_size = 96
            elif base_model == 'prajjwal1/bert-medium':
                batch_size = 48
        elif 'T4' in gpu_info or 'K80' in gpu_info:
            # 16Gb
            if base_model == 'distilbert-base-uncased':
                batch_size = 24
            elif base_model == 'prajjwal1/bert-small':
                batch_size = 64
            elif base_model == 'prajjwal1/bert-medium':
                batch_size = 28
        print(f'batch_size set to {batch_size}')

    if not os.path.exists(checkpoint_path):
        os.makedirs(checkpoint_path)
    model_path_full = ''

    if model_name == 'base':
        model_path_full = base_model
    elif model_name == 'latest':
        dir_list: List[str] = os.listdir(checkpoint_path)
        dir_list = [dir.replace('checkpoint-', '') for dir in dir_list if dir.startswith('checkpoint-')]
        if len(dir_list) == 0:
            model_path_full = base_model
        else:
            dir_list: List[int] = list(map(int, dir_list))
            max_checkpoint = max(dir_list)
            model_path_full = f'{checkpoint_path}/checkpoint-{str(max_checkpoint)}'
    else:
        dir_list: List[str] = os.listdir(checkpoint_path)
        n = f'checkpoint-{model_name}'
        if n in dir_list:
            model_path_full = f'{checkpoint_path}/checkpoint-{model_name}'
        else:
            raise ValueError(f'No Checkpoint "{n}" found in {checkpoint_path}')
    print(f'Full model name as it will be passed to transformers:' + model_path_full)

    full_train_dataset = Dataset.from_json(f'{dataset_path}/train.json')
    full_test_dataset = Dataset.from_json(f'{dataset_path}/test.json')

    cols_to_keep = ['id', 'text', target_var, 'input_ids', 'attention_mask']
    train_dataset = full_train_dataset.remove_columns([c for c in full_train_dataset.column_names if c not in cols_to_keep])
    test_dataset = full_test_dataset.remove_columns([c for c in full_test_dataset.column_names if c not in cols_to_keep])
    del full_train_dataset
    del full_test_dataset

    label_replacements = {
        'av': {
            'c2i': {'N': 0, 'L': 1, 'A': 2, 'P': 3},
            'i2c': {0: 'N', 1: 'L', 2: 'A', 3: 'P'}
        },
        'ac': {
            'c2i': {'L': 0, 'H': 1},
            'i2c': {0: 'L', 1: 'H'}
        },
        'pr': {
            'c2i': {'L': 0, 'H': 1, 'N': 2},
            'i2c': {0: 'L', 1: 'H', 2: 'N'}
        },
        'ui': {
            'c2i': {'R': 0, 'N': 1},
            'i2c': {0: 'R', 1: 'N'}
        },
        's': {
            'c2i': {'C': 0, 'U': 1},
            'i2c': {0: 'C', 1: 'U'}
        },
        'c': {
            'c2i': {'H': 0, 'N': 1, 'L': 2},
            'i2c': {0: 'H', 1: 'N', 2: 'L'}
        },
        'i': {
            'c2i': {'H': 0, 'N': 1, 'L': 2},
            'i2c': {0: 'H', 1: 'N', 2: 'L'}
        },
        'a': {
            'c2i': {'H': 0, 'N': 1, 'L': 2},
            'i2c': {0: 'H', 1: 'N', 2: 'L'}
        }
    }

    def map_char_to_int(sample):
        replacements = label_replacements[target_var]['c2i']
        return {target_var: replacements[sample[target_var]]}

    train_dataset = train_dataset.map(map_char_to_int)
    test_dataset: Dataset = test_dataset.map(map_char_to_int)
    train_dataset = train_dataset.rename_column(original_column_name=target_var, new_column_name='label')
    test_dataset = test_dataset.rename_column(original_column_name=target_var, new_column_name='label')

    train_dataset = train_dataset.shuffle(seed=42)
    test_dataset = test_dataset.shuffle(seed=42)

    number_of_labels = len(train_dataset.unique('label'))

    print(f'Read datasets:')
    print(test_dataset)
    print(train_dataset)

    model = AutoModelForSequenceClassification.from_pretrained(model_path_full, num_labels=number_of_labels)
    training_args = TrainingArguments(output_dir=checkpoint_path,
                                      evaluation_strategy=IntervalStrategy.EPOCH,
                                      per_device_train_batch_size=batch_size,
                                      per_device_eval_batch_size=batch_size,
                                      save_steps=300,
                                      save_total_limit=50,
                                      num_train_epochs=number_of_epochs)

    acc_metric = load_metric("accuracy")
    f1_metric = load_metric("f1")
    prec_metric = load_metric("precision")
    rec_metric = load_metric("recall")

    # https://towardsdatascience.com/micro-macro-weighted-averages-of-f1-score-clearly-explained-b603420b292f
    def compute_eval_metrics(eval_pred):
        logits, labels = eval_pred
        predictions = np.argmax(logits, axis=-1)
        acc_metric_result = acc_metric.compute(predictions=predictions, references=labels)
        f1_metric_result = f1_metric.compute(predictions=predictions, references=labels, average='macro')
        prec_metric_result = prec_metric.compute(predictions=predictions, references=labels, average='macro')
        rec_metric_result = rec_metric.compute(predictions=predictions, references=labels, average='macro')
        cohen_kappa = cohen_kappa_score(predictions, labels)
        cohen_kappa_result = {'cohen_kappa': cohen_kappa}
        return {**acc_metric_result, **f1_metric_result, **prec_metric_result, **rec_metric_result, **cohen_kappa_result}

    trainer = CustomEvalTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        eval_dataset=test_dataset,
        compute_metrics=compute_eval_metrics,
    )

    print(f'Created model and trainer')

    if args.action == 'train':
        print(f'Running Training')
        trainer.train()
        print('Done Training')
        model.save_pretrained(f'{checkpoint_path}/checkpoint-final')
        print('Done Saving')
    elif args.action == 'eval':
        print(f'Running Evaluation')
        eval_result = trainer.evaluate()
        res = {}
        res['predictions'] = eval_result.predictions.tolist()
        res['label_ids'] = eval_result.label_ids.tolist()
        res['metrics'] = eval_result.metrics
        # now = datetime.datetime.now().strftime("%d_%m_%Y_%H_%M_%S")
        filename = f'{eval_file_name}.json'
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        with open(filename, 'w') as fp:
            json.dump(res, fp, indent=4)
        print(f'Evaluation done. Metrics:')
        print(res['metrics'])


if __name__ == '__main__':
    main()
