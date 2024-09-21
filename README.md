# Cryptography 

Below are the essential things to know about cryptography and its algorithms
## symmetric cryptography

This type of cryptography uses a shared key (known to both sender and receiver) an thus the name symmetric cryptography
### DES : Data encryption standard

- key length = 56 bits.
- block cipher with block size of 64 bits.
- Initially the key consists of 64 bits. However, before the DES process even begins, every 8th bit is discarded to produce a 56-bit key.

### AES : Advanced encryption standard

- AES is a Block Cipher.
- The key size can be 128/192/256 bits.
- Encrypts data in blocks of 128 bits each.
- Works on bytes instead of bits (as in case of DES), thus it takes 128bits or 16 bytes of plaintext as input and generates 16 bytes of cyphered text.
#### encryption
- Treats each block of 128-bits or 16 bytes as 4byte X 4byte grid
```txt  
  [ b00 b01 b02 b03
    b10 b11 b12 b12
    b20 b21 b22 b23
    b30 b31 b32 b33 ] 
```

- The number of rounds depends on the key length as follows :
```
    128-bit key – 10 rounds
    192-bit key – 12 rounds
    256-bit key – 14 rounds
```
- Each round comprises of 4 steps :
```
    SubBytes -> each byte is substituted by another byte
    ShiftRows -> Each row is shifted a particular number of times
    MixColumns -> Each column is multiplied with a specific matrix and thus the position of each byte in the column is changed as a result. This step is skipped in the last round.
    Add Round Key -> Now the resultant output of the previous stage is XOR-ed with the corresponding round key. Here, the 16 bytes are not considered as a grid but just as 128 
                     bits of data.
```

#### decryption

- The stages in the rounds can be easily undone as these stages have an opposite to it which when performed reverts the changes.
- Each 128 blocks goes through the 10,12 or 14 rounds depending on the key size.
- The stages of each round of decryption are as follows :
```
    Add round key
    Inverse MixColumns
    ShiftRows
    Inverse SubByte
```

## Encryption algorithm

Encryption algorithm are divided into two categories based on input type, as `Block cipher` and `Stream cipher`

### Block cipher

- Takes a fixed 