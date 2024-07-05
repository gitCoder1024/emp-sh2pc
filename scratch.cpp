#include<bits/stdc++.h>
#include <emmintrin.h>  // 包含 SSE2 指令集
#include <iostream>
#include <random>
#include <cstdint>
#include "emp-tool/utils/mitccrh.h"
#include <openssl/sha.h>
using namespace std;

using block = __m128i;


inline block makeBlock(uint64_t high, uint64_t low) {
	return _mm_set_epi64x(high, low);
}

const block zero_block = makeBlock(0, 0);
const block all_one_block = makeBlock(0xFFFFFFFFFFFFFFFF,0xFFFFFFFFFFFFFFFF);
const block select_mask[2] = {zero_block, all_one_block};

// AES_KEY encryptKey;
// AES_set_encrypt_key(key, 128, &encryptKey);

// int num = 0;
// AES_cfb128_encrypt(plaintext, ciphertext, strlen((char *)plaintext), &encryptKey, iv, &num, AES_ENCRYPT);


//AES初始化

// 进行一位加法运算，用到一个and门一个XOR门（进位
// 线路编码 ： 0,1为输入，2为and输出，3为XOR输出

// 生成随机 block
block randomBlock() {
    // 使用随机数引擎生成随机数
    std::random_device rd;
    std::mt19937_64 eng(rd());
    std::uniform_int_distribution<uint64_t> distr;

    // 生成两个 64 位的随机数
    uint64_t high = distr(eng);
    uint64_t low = distr(eng);

    // 创建并返回一个 block
    return _mm_set_epi64x(high, low);
}

// 将 block 的最后一位置为 1
block setLSBToOne(block b) {
    // 创建一个仅最低位为 1 的 block
    block mask = _mm_set_epi64x(0, 1);
    
    // 将 b 的最低位设置为 1
    return _mm_or_si128(b, mask);
}

// 打印 block 内容
void printBlock(const block& b) {
    // 使用 _mm_storeu_si128 将 __m128i 存储到一个数组中
    alignas(16) uint64_t data[2];
    _mm_storeu_si128(reinterpret_cast<__m128i*>(data), b);
    uint64_t high = data[1];
    uint64_t low = data[0];
    std::cout << "Block: [" << std::hex << high << ", " << low << "]" << std::endl;
}

bool getLSB(const block & x) {
	return (x[0] & 1) == 1; // 
}

// 辅助函数：将 __m128i 转换为字节数组
void __m128i_to_bytes(const __m128i& input, unsigned char* output) {
    _mm_storeu_si128((__m128i*)output, input);
}

// 辅助函数：将字节数组转换为 __m128i
__m128i bytes_to___m128i(const unsigned char* input) {
    return _mm_loadu_si128((const __m128i*)input);
}

// 哈希函数 H：接受 __m128i 类型输入，返回 __m128i 类型输出
__m128i Hash(const __m128i& input) {
    unsigned char input_bytes[16];
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // 将 __m128i 转换为字节数组
    __m128i_to_bytes(input, input_bytes);

    // 计算 SHA-256 哈希
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input_bytes, 16); // __m128i 是 128 位 = 16 字节
    SHA256_Final(hash, &sha256);

    // 将哈希结果的前 16 字节转换回 __m128i 类型
    return bytes_to___m128i(hash);
}



// 进行一位加法运算，用到一个and门一个XOR门（进位
// 线路编码 ： 0,1为输入，2为and输出，3为XOR输出
//// 混淆方生成
////// 需要随机函数 GB_And单独写
block GBAND(block LA0, block A1, block LB0, block B1, block delta, block * table, emp::MITCCRH<8> *mitccrh) {
	bool pa = getLSB(LA0);// 标签位
	bool pb = getLSB(LB0);
	// cout << pa << pb;
	block HLA0, HA1, HLB0, HB1;
	block tmp, W0;

	block H[4];
	H[0] = LA0;
	H[1] = A1;
	H[2] = LB0;
	H[3] = B1;
	printBlock(H[0]);
    
    for(int i = 0; i < 4; i++){
        H[i] = Hash(H[i]);
    }
    // mitccrh -> hash<2,2>(H);

	HLA0 = H[0];
	HA1 = H[1];
	HLB0 = H[2];
	HB1 = H[3];

	// table 0 1分别为两个半门
	table[0] = HLA0 ^ HA1;  //
	table[0] = table[0] ^ (select_mask[pb] & delta);
	
	W0 = HLA0; //
	W0 = W0 ^ (select_mask[pa] & table[0]); // mask为0，则不变， mask为1则异或
	
	tmp = HLB0 ^ HB1;
	table[1] = tmp ^ LA0;

	W0 = W0 ^ HLB0;  // 
	W0 = W0 ^ (select_mask[pb] & tmp);
	return W0;
}

void GB(string * circuits, int length, block & R, block * F, block * e,block * gate_wires, bool * d, emp::MITCCRH<8> *mitccrh){
    R = randomBlock();
    R = setLSBToOne(R);

    for(int i = 0; i < length; i++){
        if(circuits[i].find("input") != string :: npos) e[i] = randomBlock();
        else if(circuits[i].find("XOR") != string :: npos) {
            gate_wires[1] = e[0] ^ e[1];
            d[1] = getLSB(gate_wires[1]);
        }
        else {
            gate_wires[0] = GBAND(e[0], e[0] ^ R, e[1], e[1] ^ R, R, F, mitccrh);
            d[0] = getLSB(gate_wires[0]);
        }
    }
}



void EN(bool a, bool b, block * e, unordered_map<string, block> & buffer, block R){
    buffer["alice"] = e[0] ^ (select_mask[a] & R);
    buffer["bob"] = e[1] ^ (select_mask[b] & R);
    
   
}

block* EV(unordered_map<string, block> & buffer){
    block A = buffer["alice"], B = buffer["bob"];
    buffer["AND"] = A ^ B;
    

    block HA, HB, W;
	int sa, sb;

	sa = getLSB(A);
	sb = getLSB(B);

	block H[2];
	
	HA = Hash(A);
	HB = Hash(B);

	W = HA ^ HB;
	W = W ^ (select_mask[sa] & buffer["table0"]); //用颜色比特识别解密
	W = W ^ (select_mask[sb] & buffer["table1"]);
	W = W ^ (select_mask[sb] & A);

    buffer["XOR"] = W;
}

//// Encoding 需要OT

//// 计算方计算

//// Decoding 得到结果


// io 通信 通过map实现 map<string, string> buffer(OT简化为 两个字符串的选择)

// main函数, 参与方和数据初始化，整个过程  上面的功能函数的return值直接放到变量里

int main(){
    
    emp :: MITCCRH<8> hash;
    hash.setS(randomBlock());
    

    bool a = 1, b = 0; 
    block alice = randomBlock(), bob = randomBlock();
    // printBlock(alice);
    // printBlock(bob);
    string circuits[4] = {"input1", "input2", "outputAND", "outputXOR"};
    int length = 4;
    block e[2];
    block gate_wires[2];
    bool d[2];
    block F[2];
    block R;
    

    unordered_map<string, block> buffer;

    GB(circuits, length, R, F, e, gate_wires, d , &hash);
    
    EN(a, b, e, buffer, R);     

    buffer["table0"] = F[0];
    buffer["table1"] = F[1];

    EV(buffer);

    cout << a << " + " << b << " = " << (getLSB(buffer["AND"]) ^ d[0]) << (getLSB(buffer["XOR"]) ^ d[1]) << endl;





    

    return 0;
}
