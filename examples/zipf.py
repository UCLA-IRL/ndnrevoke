import numpy as np
import os

sample = np.random.zipf(2, 5000)
while(len(np.unique(sample)) != 100):
    sample = np.random.zipf(2, 5000)
mappings = [[index, key] for index, key in enumerate(np.unique(sample))]
rebased = [[mapping[1] for mapping in mappings].index(item) for item in sample]
print(rebased)
# print([rebased.count(i) for i in range(0, 99)])
filename = os.path.join(os.getcwd(), 'zipf-100-2.seq')
with open(filename, 'w') as wf:
    for item in rebased:
        wf.write(str(item) + '\n')
    