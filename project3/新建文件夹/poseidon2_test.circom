pragma circom 2.2.2;

template Poseidon2() {
    signal input in[2];
    signal output out;
    
    // 参数
    var t = 2;
    var d = 5;
    var rounds = 4;
    
    // 常数
    var RC[4][2] = [[1,1], [2,2], [3,3], [4,4]];
    var MDS[2][2] = [[1,2], [2,1]];
    
    // 状态信号
    signal state[rounds+1][t];
    
    // 初始化
    state[0][0] <== in[0];
    state[0][1] <== in[1];
    
    // 在初始作用域声明所有需要的组件
    component sboxes[rounds]; // 为每轮声明一个S-box
    
    // 主循环
    for (var r = 0; r < rounds; r++) {
        // 使用预先声明的组件
        sboxes[r] = SBox();
        sboxes[r].in <== state[r][0] + RC[r][0];
        
        state[r+1][0] <== MDS[0][0] * sboxes[r].out + MDS[0][1] * (state[r][1] + RC[r][1]);
        state[r+1][1] <== MDS[1][0] * sboxes[r].out + MDS[1][1] * (state[r][1] + RC[r][1]);
    }
    
    out <== state[rounds][0];
}

template SBox() {
    signal input in;
    signal output out;
    signal x2 <== in * in;
    signal x4 <== x2 * x2;
    out <== in * x4;
}

component main = Poseidon2();
