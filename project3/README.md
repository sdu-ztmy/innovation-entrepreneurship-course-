# **Poseidon2 哈希函数 Circom 实现解析**

## **1. 概述**
Poseidon 是一种专为零知识证明（ZKP）设计的哈希函数，具有低算术复杂度，适用于 zk-SNARKs 和 zk-STARKs 等证明系统。该报告详细解释了一个简化版 **Poseidon2** 的 Circom 实现原理，不涉及具体代码，而是从算法结构和数学角度分析其设计。

---

## **2. Poseidon2 的核心结构**
Poseidon2 是一种 **海绵构造（Sponge Construction）** 的变种，但在这个实现中，它被简化为一个 **置换网络（Permutation Network）**，包含以下关键部分：
1. **输入**：2 个有限域元素（`in[0]`, `in[1]`）。
2. **输出**：1 个有限域元素（`out`）。
3. **轮数（Rounds）**：4 轮置换。
4. **状态（State）**：2 个元素的数组，在每轮运算后更新。

---

## **3. 算法流程**
### **(1) 初始化**
- 输入的两个信号 `in[0]` 和 `in[1]` 被加载到初始状态 `state[0][0]` 和 `state[0][1]`。

### **(2) 轮函数（Round Function）**
每轮运算包含两个主要操作：
1. **S-box（非线性变换）**：
   - 对状态的一部分（`state[r][0]`）应用 **五次幂（\(x^5\)）** 运算，增加非线性。
   - 同时，该运算会加上一个 **轮常数（Round Constant, RC）** 以打破对称性。
   
2. **MDS 矩阵乘法（线性扩散）**：
   - 使用 **最大距离可分离（MDS）矩阵** 对状态进行线性混合，确保输入的变化能影响所有输出。
   - 该矩阵确保即使单个输入位变化，也会影响整个状态。

### **(3) 最终输出**
- 经过 4 轮运算后，取 `state[rounds][0]` 作为最终哈希输出。

---

## **4. 安全性分析**
1. **抗碰撞性**：
   - 由于 S-box 的非线性特性和 MDS 矩阵的扩散性，很难找到两个不同的输入产生相同的输出。
   
2. **抗预映射攻击**：
   - 由于 \(x^5\) 在有限域上是单向的，反向计算困难。

3. **抗差分攻击**：
   - 轮常数和 MDS 矩阵的组合使得差分攻击难以进行。

---

## **5. 运行结果**

![image](https://github.com/sdu-ztmy/innovation-entrepreneurship-course-/blob/main/project3/img/14fa8bed53b44ae5d4cd7e459200666c.png)

# 用Groth16算法生成证明

## 1. 编译电路
circom poseidon2_t2.circom --r1cs --wasm --sym

## 2. 生成 witness
node poseidon2_t2_js/generate_witness.js poseidon2_t2_js/poseidon2_t2.wasm input.json witness.wtns

## 3. 创建ptau文件                                                                                                                                                                snarkjs powersoftau new bn128 12 aaa.ptau -v
snarkjs powersoftau contribute aaa.ptau bbb.ptau --name="mxh" -v
snarkjs powersoftau verify bbb.ptau
snarkjs powersoftau prepare phase2 bbb.ptau bbb.ptau -v

## 4. Groth16 setup
snarkjs groth16 setup build/poseidon2_t2.r1cs powersOfTau28_hez_final_12.ptau poseidon2_t2_0000.zkey

## 5. 导出验证密钥
snarkjs zkey export verificationkey poseidon2_t2_0000.zkey verification_key.json

## 6. 生成证明
snarkjs groth16 prove poseidon2_t2_0000.zkey build/witness.wtns proof.json public.json

## 7. 验证证明
snarkjs groth16 verify verification_key.json public.json proof.json

## 8. 运行结果 


![image](https://github.com/sdu-ztmy/innovation-entrepreneurship-course-/blob/main/project3/img/199b8e25d2bd473cfe05accf323839da.png)
