#ifndef __BOX_CLASSIFIER_H
#define __BOX_CLASSIFIER_H

/* Combined score threshold: spatial_score + meta_score >= threshold → malicious.
 * Range [0, 2]. Tune post-training; placeholder classifiers always return 0. */
#define BOX_EVAL_THRESHOLD  1.0f

/* Spatial Decision Tree: returns attack probability in [0, 1].
 * box layout: [min_f0, max_f0, min_f1_us, max_f1_us] (inverse-transformed coords) */
float classify_box_spatial(float *box);

/* Meta Scoring Function (logistic regression): returns attack probability in [0, 1].
 * box_ratio   = box_points / SAMPLE_WINDOW  (flow fraction)
 * box_volume  = raw axis-aligned box volume in feature space
 * delta_points = box_points_now - box_points_prev_window (0 on first window)
 * Features used internally: [box_ratio, box_ratio², box_volume, delta_points] */
float score_box_meta(float box_ratio, float box_volume, int delta_points);

#endif /* __BOX_CLASSIFIER_H */
