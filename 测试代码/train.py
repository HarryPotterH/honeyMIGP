from itertools import combinations
import numpy as np
import string
import json
import csv
import itertools
import time
from word2keypress import distance, Keyboard
from ast import literal_eval


# password与password1 [('i', '1', 8)]-->[('i', '1', -1)],keyboard版
# 支持location为负数时的情形
# 增设了当distance大于3时，bin再计算它的路径
# 最终返回的是distance和编辑路径
def get_my_path(str1, str2):
    kb = Keyboard()
    str1 = kb.word_to_keyseq(str1)
    str2 = kb.word_to_keyseq(str2)
    # Definitions:
    n = len(str1)
    m = len(str2)
    D = np.full((n + 1, m + 1), np.inf)
    op_arr_str = ["d", "i", "c", "s"]
    trace = np.full((n + 1, m + 1), None)
    for i in range(1, n + 1):
        trace[i, 0] = (i - 1, 0)
    for j in range(1, m + 1):
        trace[0, j] = (0, j - 1)
    # Initialization:
    for i in range(n + 1):
        D[i, 0] = i
    for j in range(m + 1):
        D[0, j] = j
    # Fill the matrices:
    for i in range(1, n + 1):
        for j in range(1, m + 1):
            delete = D[i - 1, j] + 1
            insert = D[i, j - 1] + 1
            if (str1[i - 1] == str2[j - 1]):
                sub = np.inf
                copy = D[i - 1, j - 1]
            else:
                sub = D[i - 1, j - 1] + 1
                copy = np.inf
            op_arr = [delete, insert, copy, sub]
            D[i, j] = np.min(op_arr)
            op = np.argmin(op_arr)
            if (op == 0):
                # delete, go down
                trace[i, j] = (i - 1, j)
            elif (op == 1):
                # insert, go left
                trace[i, j] = (i, j - 1)
            else:
                # copy or subsitute, go diag
                trace[i, j] = (i - 1, j - 1)

    if (D[n, m] >= 4):
        return D[n, m], "we won't take it"

    # Find the path of transitions:
    i = n
    j = m
    cursor = trace[i, j]
    path = []
    while (cursor is not None):
        # 3 possible directions:

        if (cursor[0] == i - 1 and cursor[1] == j - 1):
            negative = -(n - cursor[0])  # cursor[0]是正的数，negative是对应负数
            # diagonal - sub or copy
            if (str1[cursor[0]] != str2[cursor[1]]):
                # substitute  str2[cursor[1]]是替换字符  cursor[0]（i-1）是原口令被替换位置的下标
                if abs(negative) < cursor[0]:
                    path.append(("s", str2[cursor[1]], negative))
                else:
                    path.append(("s", str2[cursor[1]], cursor[0]))
            i = i - 1
            j = j - 1

        elif (cursor[0] == i and cursor[1] == j - 1):
            negative = -(n + 1 - cursor[0])  # cursor[0]是正的数，negative是对应负数
            # go left - insert
            if abs(negative) < cursor[0]:
                path.append(("i", str2[cursor[1]], negative))
            else:
                path.append(("i", str2[cursor[1]], cursor[0]))
            j = j - 1

        else:
            negative = -(n - cursor[0])  # cursor[0]是正的数，negative是对应负数
            # (cursor[0] == i - 1 and cursor[1] == j )
            # go down - delete
            if abs(negative) < cursor[0]:
                path.append(("d", None, negative))
            else:
                path.append(("d", None, cursor[0]))
            i = i - 1
        cursor = trace[cursor[0], cursor[1]]
    return D[n, m], list(reversed(path))


def learn_my_path(infile, outfile1, outfile2, outfile3):
    fin = open(infile, 'r', encoding="UTF-8")

    line = fin.readline()
    transition_count_1 = {}
    transition_count_2 = {}
    transition_count_3 = {}
    count=0

    while line:
        count+=1
        if count % 1000 == 0:
            print("Done: {}".format(count))
        if count>100000:
            break

        sim_pw_pair = line.split(":")[1][:-1].split(",")
        # [:-1]是去掉结尾的换行符
        iter_pws = combinations(sim_pw_pair, 2)  # 提取这一组口令中的每对口令
        for i in iter_pws:
            pairs = list(i)
            distance, path = get_my_path(pairs[0], pairs[1])
            if distance > 3:
                continue
            elif distance == 1:
                path_list = []
                for e in path:
                    path_list.append(str(e))
                path_str = "+".join(path_list)

                if path_str not in transition_count_1:
                    transition_count_1[path_str] = 1
                else:
                    transition_count_1[path_str] += 1

            elif distance == 2:
                path_list = []
                for e in path:
                    path_list.append(str(e))
                path_str = "+".join(path_list)

                if path_str not in transition_count_2:
                    transition_count_2[path_str] = 1
                else:
                    transition_count_2[path_str] += 1

            elif distance == 3:
                path_list = []
                for e in path:
                    path_list.append(str(e))
                path_str = "+".join(path_list)

                if path_str not in transition_count_3:
                    transition_count_3[path_str] = 1
                else:
                    transition_count_3[path_str] += 1

        line = fin.readline()
    with open(outfile1, 'w', encoding="UTF-8") as fout1:
        json.dump(transition_count_1, fout1, indent=3)
    with open(outfile2, 'w', encoding="UTF-8") as fout2:
        json.dump(transition_count_2, fout2, indent=3)
    with open(outfile3, 'w', encoding="UTF-8") as fout3:
        json.dump(transition_count_3, fout3, indent=3)

    return

start=time.clock()


# file="C:/科研/4IQ_similarity.txt"
# outfile1="C:/科研/transition_count_1.json"
# outfile2="C:/科研/transition_count_2.json"
# outfile3="C:/科研/transition_count_3.json"
# learn_my_path(file,outfile1,outfile2,outfile3)

end=time.clock()
print("final is in ",end-start)