# Common vulnerability scoring system prediction based on open source intelligence information sources

This repository hosts the code used in the paper _Common vulnerability scoring system prediction based on open source intelligence information sources_ [1], which was originally a master's thesis by David Relke.

[1]: Kuehn, P., Relke, D. N., & Reuter, C. (2023). Common vulnerability scoring system prediction based on open source intelligence information sources. Computers & Security. https://doi.org/10.1016/j.cose.2023.103286


## Requirements

- Python 3.10
- Pipenv
- [Gecko or Chrome Driver](https://www.selenium.dev/documentation/webdriver/getting_started/install_drivers/)
- For Remote Driver: Docker

## Web Scraping

**Define Sources** 
In main.py with `sources = ['zerodayinitiative.com', 'ibm.com', 'tools.cisco.com', 'support.f5.com', 'www.qualcomm.com', 'www.intel.com', 'talosintelligence.com', 'snyk.io']`

MongoDB will return all referenced URLs that match the sources.
By default, all URLs are returned, even if there is already text from a previous run.
This behavior can be adjusted with the parameters of _MongoHandler.get_reference_list_for_url_.
Possible options: _only_scraped_ (only references that have already been visited), _only_not_scraped_ (only references that have not yet been visited) and _only_scraped_but_no_text_ (only references that have already been visited and for which there is still no text).

**Number of Threads**

The default is `NUMBER_OF_THREADS = 4` and can be adjusted there.
It corresponds to the number of Selenium Firefox WebDrivers that are started.


## Classifier

`cvss_predictor.py` supports two tasks: `train` and `eval`

The following parameters must be set:

**--target**: The target variable, i.e. the CVSS component. One from `['av', 'ac', 'pr', 'ui', 's', 'c', 'i', 'a']`

**--checkpoint_path**: The file path under which the models are located or should be stored

**--model_checkpoint**: The checkpoint to be used for further training or evaluation. 'latest' uses the most recent, 'base' the untrained base model, otherwise the iteration number of the checkpoint.

**--base_model**: The base model. Provided are `['distilbert-base-uncased', 'prajjwal1/bert-small', 'prajjwal1/bert-medium']`.

**--eval_file**: The file in which the results of the evaluation are saved. `.json` is automatically attached.

**--dataset_path**: Path to the folder containing `test.json` and `train.json`.

**--epochs**: Optional number of epochs to be trained for.

Examples:

`python cvss_predictor.py eval --target av --checkpoint_path "path/to/models" --model_checkpoint final --base_model "distilbert-base-uncased" --eval_file "my/eval/dir/res_distil_av", --dataset_path "my/distilbert/dataset/path"`

Will execute evaluation for AV on the last checkpoint of the DistilBERT model in `path/to/models` and write the result to `my/eval/dir/res_distil_av.json`. The data set `my/distilbert/dataset/path/test.json` is used for the evaluation.

`python cvss_predictor.py train --target ui --checkpoint_path "path/to/models" --model_checkpoint base --base_model "prajjwal1/bert-medium" --eval_file "my/eval/dir/res_bert-medium_ui", --dataset_path "my/bert_medium/dataset/path" --epochs 6`

Will train the untrained Bert-medium model for UI with the dataset `my/bert_medium/dataset/path/train.json` for 6 epochs and store the checkpoints in `path/to/models`.

## Citing

If you make use of this code in your work, please cite the following paper:

```
@article{Kuehn_Relke_Reuter_2023,
    title={Common vulnerability scoring system prediction based on open source intelligence information sources},
    rights={All rights reserved},
    ISSN={0167-4048},
    url={https://www.sciencedirect.com/science/article/pii/S0167404823001967},
    DOI={10.1016/j.cose.2023.103286},
    journal={Computers & Security},
    author={Kuehn, Philipp and Relke, David N. and Reuter, Christian},
    year={2023}
}
```

## Contributors

- Philipp Kühn
- David Relke
- Christian Reuter

## Acknowledgements

This work was supported by the German Federal Ministry for Education and Research (BMBF) in the project CYWARN (13N15407) and German Federal Ministry of Education and Research and the Hessian Ministry of Higher Education, Research, Science and the Arts within their joint support of the National Research Center for Applied Cybersecurity ATHENE.

## License

MIT License

Copyright (c) 2024 Philipp Kühn

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
