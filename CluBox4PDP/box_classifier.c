#include <math.h>
#include "box_classifier.h"

/* Logistic Regression meta-scoring model.
 * Features: [box_ratio, box_ratio², box_volume, delta_points]
 *   box_ratio  = box_points / SAMPLE_WINDOW
 *   box_volume = raw axis-aligned box volume in feature space
 * Trained: attack_ratio >= 0.50, box_ratio >= 0.01 filter;
 * data: output_20260420_074137/233/330 (87 windows, 195 boxes) */
static const float LR_MEAN[4]  = {0.438717f, 0.342883f, 103849.577484f, 1236.723077f};
static const float LR_SCALE[4] = {0.387828f, 0.422624f, 115622.284115f, 2896.885439f};
static const float LR_W[4]     = {3.372171f, -1.589807f, -2.610595f, 0.025580f};
static const float LR_BIAS     = -0.710509f;

float score_box_meta(float box_ratio, float box_volume, int delta_points)
{
    if (box_ratio < 0.01f)
        return 0.0f;
    float x[4] = { box_ratio, box_ratio * box_ratio, box_volume, (float)delta_points };
    float z = LR_BIAS;
    for (int i = 0; i < 4; i++)
        z += LR_W[i] * (x[i] - LR_MEAN[i]) / LR_SCALE[i];
    return 1.0f / (1.0f + expf(-z));
}

/* Decision Tree spatial classifier.
 * Features: b[0]=min_f0, b[1]=max_f0, b[2]=min_f1_us, b[3]=max_f1_us
 * Trained: attack_ratio >= 0.50, depth=5;
 * data: output_20260420_074137/233/330
 * Key rule: attack (UDP flood) has max_IAT ≤ 5µs after pcap timestamp scaling */
float classify_box_spatial(float *b)
{
    if (b[3] <= 5.00f)
        return 1.0f;
    return 0.0f;
}
