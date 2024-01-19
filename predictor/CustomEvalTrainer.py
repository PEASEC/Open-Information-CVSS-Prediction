import math
import time
from typing import Optional, List, Dict

from datasets import Dataset
from transformers import Trainer
from transformers.trainer_utils import speed_metrics


class CustomEvalTrainer(Trainer):
    def evaluate(
            self,
            eval_dataset: Optional[Dataset] = None,
            ignore_keys: Optional[List[str]] = None,
            metric_key_prefix: str = "eval",
    ) -> Dict[str, float]:
        """
        Run evaluation and returns metrics.
        The calling script will be responsible for providing a method to compute metrics, as they are task-dependent
        (pass it to the init `compute_metrics` argument).
        You can also subclass and override this method to inject custom behavior.
        Args:
            eval_dataset (`Dataset`, *optional*):
                Pass a dataset if you wish to override `self.eval_dataset`. If it is an `datasets.Dataset`, columns not
                accepted by the `model.forward()` method are automatically removed. It must implement the `__len__`
                method.
            ignore_keys (`Lst[str]`, *optional*):
                A list of keys in the output of your model (if it is a dictionary) that should be ignored when
                gathering predictions.
            metric_key_prefix (`str`, *optional*, defaults to `"eval"`):
                An optional prefix to be used as the metrics key prefix. For example the metrics "bleu" will be named
                "eval_bleu" if the prefix is "eval" (default)
        Returns:
            A dictionary containing the evaluation loss and the potential metrics computed from the predictions. The
            dictionary also contains the epoch number which comes from the training state.
        """
        # memory metrics - must set up as early as possible
        self._memory_tracker.start()

        eval_dataloader = self.get_eval_dataloader(eval_dataset)
        start_time = time.time()

        eval_loop = self.prediction_loop if self.args.use_legacy_prediction_loop else self.evaluation_loop
        output = eval_loop(
            eval_dataloader,
            description="Evaluation",
            # No point gathering the predictions if there are no metrics, otherwise we defer to
            # self.args.prediction_loss_only
            prediction_loss_only=True if self.compute_metrics is None else None,
            ignore_keys=ignore_keys,
            metric_key_prefix=metric_key_prefix,
        )

        total_batch_size = self.args.eval_batch_size * self.args.world_size
        output.metrics.update(
            speed_metrics(
                metric_key_prefix,
                start_time,
                num_samples=output.num_samples,
                num_steps=math.ceil(output.num_samples / total_batch_size),
            )
        )

        self.log(output.metrics)

        self.control = self.callback_handler.on_evaluate(self.args, self.state, self.control, output.metrics)

        self._memory_tracker.stop_and_update_metrics(output.metrics)

        return output
