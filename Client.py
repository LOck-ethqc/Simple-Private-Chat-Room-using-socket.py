# ------------------------------------------------------------------------------
# Copyright (c) 2024, LOckETHQC
# All rights reserved.
#
# This file is part of LOck-ethqc Github Repository Simple-Private-Chat-Room-using-socket.py
# ------------------------------------------------------------------------------
import socket
import math

def Buffer(msg):
    if (len(msg) < 16): #Makes sure the length of the message provided is less than 16 characters.
        padded_msg = ''
        padded_msg = msg.ljust((16), 'z') #Pads a bunch of Z letters till the message containt 16 characters.
        return padded_msg
    else:
        return msg

#-----------------------------------------------------Vigenère cipher--------------------------------------------------------------------------
def Vigenere_Encryption(m,k):
    global alphabit
    Ciphertxt = '' #The string that will hold the POST-Encryption characters/alphabits.
    for index, m_index in enumerate(m): #Assigns two variables and scans the characters of the plaintext.
        msg_index = alphabit.index(m_index) #The Plaintext characters' indexes.
        #print("MSG index:", msg_index)
        key_index = alphabit.index(k[index]) #The Key characters' indexes.
        #print("Key index:", key_index)
        cipher_index = (msg_index + key_index) % 26 #Vigenere's Mathematical equation for Encryption.
        #print("Vigenere Encryption Equation Result:", cipher_index, "=", chr(cipher_index + 97))
        Ciphertxt = Ciphertxt + alphabit[cipher_index] #Appends the encrypted characters into a string.
        #print("Vigenere Cipher Text:", Ciphertxt)
        #print("- - - -")
    return (Ciphertxt)

def Vigenere_Decryption(c, k):
    global alphabit
    Decryptiontxt = '' #The string that will hold the POST-Decryption characters/alphabits.
    for index, c_index in enumerate(c):
        ciphermsg_index = alphabit.index(c_index) #The Ciphertxt characters' indexes.
        #print("Ciphermsg index:", ciphermsg_index)
        key_index = alphabit.index(k[index])
        #print("Key index:", key_index)
        cipher_index = (ciphermsg_index - key_index) % 26 #Vigenere's Mathematical equation for Decryption.
        #print("Vvigenere Decryption Equation Result:", cipher_index, "=", chr(cipher_index + 97))
        Decryptiontxt = Decryptiontxt + alphabit[cipher_index] #Appends the decrypted characters into a string.
        #print("Vigenere Decrypted Text:", Decryptiontxt)
        #print("- - - -")
    return Decryptiontxt


#-----------------------------------------------------CONVERSIONS-----------------------------------------------------------------------

def Text_to_ASCII(ECP):
    ascii_list = [] #The list that will hold the ASCII value.
    for i in ECP:
        ascii_list.append(ord(i)) #The conversion function.
    return ascii_list

#def ASCII_to_Text(ASCII):
    #text = ''.join(chr(int(code)) for code in ASCII)
    #return text

def ASCII_to_Binary(ASCII):
    binary_list = [] #The list that will hold the Binary value.
    for i in ASCII:
        binary_list.append(format(i, '08b')) #(old method)The conversion function. #'[2:]' means to start from the second index till the end, ignoring "0b"
    return binary_list

def binary_to_ascii(binary_list):
    # Join binary strings together to form a single binary string
    binary_string = ''.join(binary_list)
    # Split binary string into 8-bit chunks
    chunks = [binary_string[i:i + 8] for i in range(0, len(binary_string), 8)]
    # Convert each 8-bit chunk to ASCII character
    ascii_string = ''.join([chr(int(chunk, 2)) for chunk in chunks])
    return ascii_string

def Binary_to_Hexa(Binary):
    hexa_list = [] #The list that will hold the Hexa Decimal value.
    #for i in Binary:
        #hexa_list.append(format(int(i,2), 'x')) #The conversion function.
    #return hexa_list
    #ABOVE is the old code which had a problem in converting where in some complex cases it converts the 8-bits to 1 digit of hexa value.
    #The difference between 'x' and '02x' is that the latter specifies that the output should be at least two characters.
    for i in Binary:
        hexa_list.append(format(int(i, 2), '02x'))  # Convert each binary string to a two-digit hexadecimal representation
    return hexa_list

def Hexa_to_Binary(Hexa):
    binary_list = [] #The list that will hold the Hexa Decimal value.
    for hex_string in Hexa:
        binary_list.append(format(int(hex_string, 16), '08b'))
    return binary_list


#-----------------------------------------------------AES-------------------------------------------------------------------------------
# FIRST PHASE OF AES: BLOCK TO STATE.
def Block_to_State(BTH):
    State = [1,2,3,4],[5,6,7,8],[9,10,11,12],[13,14,15,16] #State List that will hold the HexaDecimal value.
    #test = [11, 22, 33, 44, 55, 66, 77, 88, 99,1010,1111,1212,1313,1414,15155,1616]
    # Every 4 values in BTH is stored separately in each column.
    State = [[BTH[i], BTH[i+4], BTH[i+8], BTH[i+12]] for i in range(4)]
    return(State)

# SECOND PHASE OF AES: ADD ROUND KEY.
def AddRoundKey(State):
    #KEY: malikabdulahslow
    Key = ['01101101', '01100001', '01101100', '01101001',
    '01101011', '01100001', '01100010', '01100100',
    '01110101', '01101100', '01100001', '01101000',
    '01110011', '01101100', '01101111', '01110111']

    Flat_State = [item for sublist in State for item in sublist] #iterates over each sublist, combining them into a new List.
    #print("Flat_State:", Flat_State)
    Binary_State = Hexa_to_Binary(Flat_State)
    #print("Binary State:", Binary_State)

    for i in range(16): #iterates through 0-15 indexes.
        xor_op=int(Binary_State[i], 2)^int(Key[i], 2) #XOR operation.
        #print(xor_op)
        Binary_State[i]=format(xor_op, '08b') #Stores the XORed result.
        #print(Binary_State[i])
    return(Binary_State)
  
# PHASE THREE OF AES: SUB BYTE.
def SubByte(XORed_bin_State):
    S_Box = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16],
]
    
    XORed_State=Binary_to_Hexa(XORed_bin_State)
    #print("XORed State (Hexa):", XORed_State)
    SubByte_list = []
    for i in XORed_State:
        row = int(i[0], 16)  # Extract the first digit as the row.
        col = int(i[1], 16)  # Extract the second digit as the column.
        SubByte_list.append(format(S_Box[row][col], '02x'))
    return SubByte_list

# PHASE FOUR OF AES: SHIFT ROWS.
def Shift_Rows(SubByte_State):
    #r0 is never shifted.
    #r1 is shifted once.
    ShiftAID=SubByte_State[4]
    SubByte_State[4]=SubByte_State[5]
    SubByte_State[5]=SubByte_State[6]
    SubByte_State[6]=SubByte_State[7]
    SubByte_State[7]=ShiftAID
    #r2 is shifted twice.
    ShiftAID2=SubByte_State[8]
    ShiftAID3=SubByte_State[9]
    SubByte_State[8]=SubByte_State[10]
    SubByte_State[9]=SubByte_State[11]
    SubByte_State[10]=ShiftAID2
    SubByte_State[11]=ShiftAID3
    #r3 is shifted thrice
    ShiftAID4=SubByte_State[15]
    SubByte_State[15]=SubByte_State[14]
    SubByte_State[14]=SubByte_State[13]
    SubByte_State[13]=SubByte_State[12]
    SubByte_State[12]=ShiftAID4
    return(SubByte_State)
  

# PHASE FIVE OF AES: MIX COLUMNS
def mix_column(column):
    def galois_mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p % 256

    result = []
    for i in range(4):
        result.append(
            galois_mul(2, column[i]) ^ galois_mul(3, column[(i + 1) % 4]) ^ column[(i + 2) % 4] ^ column[(i + 3) % 4])

    return result

def mix_columns(state):
    mixed_state = []
    for i in range(4):
        column = state[i*4:(i+1)*4] #Chunks it up to 4 groups of 4
        mixed_column = mix_column(column)
        mixed_state.extend(mixed_column)
    return mixed_state

##################################################### AES DECRYPTION #################################################################3
######MIX COLUMNS DECRYPTION
def inv_mix_column(column):
    def galois_mul(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # AES irreducible polynomial x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p % 256

    result = []
    for i in range(4):
        result.append(
            galois_mul(0x0E, column[i]) ^ galois_mul(0x0B, column[(i + 1) % 4]) ^ 
            galois_mul(0x0D, column[(i + 2) % 4]) ^ galois_mul(0x09, column[(i + 3) % 4])
        )

    return result

def inv_mix_columns(state):
    inv_mixed_state = []
    for i in range(4):
        column = state[i*4:(i+1)*4]
        inv_mixed_column = inv_mix_column(column)
        inv_mixed_state.extend(inv_mixed_column)
    return inv_mixed_state

#####SHIFT ROWS DECRYPTION
def inv_shift_rows(SubByte_State):
    #r0 is never shifted.
    #r1 is shifted once.
    ShiftAID=SubByte_State[7]
    SubByte_State[7]=SubByte_State[6]
    SubByte_State[6]=SubByte_State[5]
    SubByte_State[5]=SubByte_State[4]
    SubByte_State[4]=ShiftAID
    #r2 is shifted twice.
    ShiftAID2=SubByte_State[8]
    ShiftAID3=SubByte_State[9]
    SubByte_State[8]=SubByte_State[10]
    SubByte_State[9]=SubByte_State[11]
    SubByte_State[10]=ShiftAID2
    SubByte_State[11]=ShiftAID3
    #r3 is shifted thrice
    ShiftAID4=SubByte_State[12]
    SubByte_State[12]=SubByte_State[13]
    SubByte_State[13]=SubByte_State[14]
    SubByte_State[14]=SubByte_State[15]
    SubByte_State[15]=ShiftAID4
    return(SubByte_State)

#####SUB BYTE DECRYTPION
def inv_sub_bytes(SubByte_State):
    inv_S_Box = [
        [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
        [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
        [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
        [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
        [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
        [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
        [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
        [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
        [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
        [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
        [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
        [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
        [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
        [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
        [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D],
    ]

    inv_SubByte_list = []
    for i in SubByte_State:
        row = int(i[0], 16)  # Extract the first digit as the row.
        col = int(i[1], 16)  # Extract the second digit as the column.
        inv_SubByte_list.append(format(inv_S_Box[row][col], '02x'))
    return inv_SubByte_list
  
###ADD ROUND KEY DECRYPTION
def inv_AddRoundKey(State):
    #KEY: malikabdulahslow
    Key = ['01101101', '01100001', '01101100', '01101001',
    '01101011', '01100001', '01100010', '01100100',
    '01110101', '01101100', '01100001', '01101000',
    '01110011', '01101100', '01101111', '01110111']
    Bin_State = Hexa_to_Binary(State)
    for i in range(16): #iterates through 0-15 indexes.
        xor_oper=int(Bin_State[i], 2)^int(Key[i], 2) #XOR operation.
        #print(xor_op)
        Bin_State[i]=format(xor_oper, '08b') #Stores the XORed result.
        #print(Binary_State[i])
    return(Bin_State)
      
#################
def inv_Block_to_State(BTH):
    State = [1,2,3,4],[5,6,7,8],[9,10,11,12],[13,14,15,16] #State List that will hold the HexaDecimal value.
    #test = [11, 22, 33, 44, 55, 66, 77, 88, 99,1010,1111,1212,1313,1414,15155,1616]
    # Every 4 values in BTH is stored separately in each column.
    State = [[BTH[i], BTH[i+4], BTH[i+8], BTH[i+12]] for i in range(4)]
    return(State)


#----------------------------------------------------------MD5 Hash--------------------------------------------------------------------------------
# This list maintains the amount by which to rotate the buffers during processing stage
rotate_by = [7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
			 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
			 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
			 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21]

# This list maintains the additive constant to be added in each processing step.
constants = [int(abs(math.sin(i+1)) * 4294967296) & 0xFFFFFFFF for i in range(64)]

# STEP 1: append padding bits s.t. the length is congruent to 448 modulo 512
# which is equivalent to saying 56 modulo 64.
# padding before adding the length of the original message is conventionally done as:
# pad a one followed by zeros to become congruent to 448 modulo 512(or 56 modulo 64).
def pad(msg):
	msg_len_in_bits = (8*len(msg)) & 0xffffffffffffffff #fixed length to 64-bits
	msg.append(0x80)

	while len(msg)%64 != 56:
		msg.append(0)

# STEP 2: append a 64-bit version of the length of the length of the original message
# in the unlikely event that the length of the message is greater than 2^64,
# only the lower order 64 bits of the length are used.

# sys.byteorder -> 'little'
	msg += msg_len_in_bits.to_bytes(8, byteorder='little') # little endian convention
	# to_bytes(8...) will return the lower order 64 bits(8 bytes) of the length.
	
	return msg


# STEP 3: initialise message digest buffer.
# MD buffer is 4 words A, B, C and D each of 32-bits.

init_MDBuffer = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

# UTILITY/HELPER FUNCTION:
def leftRotate(x, amount):
	x &= 0xFFFFFFFF
	return (x << amount | x >> (32-amount)) & 0xFFFFFFFF


# STEP 4: process the message in 16-word blocks
# Message block stored in buffers is processed in the follg general manner:
# A = B + rotate left by some amount<-(A + func(B, C, D) + additive constant + 1 of the 16 32-bit(4 byte) blocks converted to int form)

def processMessage(msg):
	init_temp = init_MDBuffer[:] # create copy of the buffer init constants to preserve them for when message has multiple 512-bit blocks
	
	# message length is a multiple of 512bits, but the processing is to be done separately for every 512-bit block.
	for offset in range(0, len(msg), 64):
		A, B, C, D = init_temp # have to initialise MD Buffer for every block
		block = msg[offset : offset+64] # create block to be processed
		# msg is processed as chunks of 16-words, hence, 16 such 32-bit chunks
		for i in range(64): # 1 pass through the loop processes some 32 bits out of the 512-bit block.
			if i < 16:
				# Round 1
				func = lambda b, c, d: (b & c) | (~b & d)
				# if b is true then ans is c, else d.
				index_func = lambda i: i

			elif i >= 16 and i < 32:
				# Round 2
				func = lambda b, c, d: (d & b) | (~d & c)
				# if d is true then ans is b, else c.
				index_func = lambda i: (5*i + 1)%16

			elif i >= 32 and i < 48:
				# Round 3
				func = lambda b, c, d: b ^ c ^ d
				# Parity of b, c, d
				index_func = lambda i: (3*i + 5)%16
			
			elif i >= 48 and i < 64:
				# Round 4
				func = lambda b, c, d: c ^ (b | ~d)
				index_func = lambda i: (7*i)%16

			F = func(B, C, D) # operate on MD Buffers B, C, D
			G = index_func(i) # select one of the 32-bit words from the 512-bit block of the original message to operate on.

			to_rotate = A + F + constants[i] + int.from_bytes(block[4*G : 4*G + 4], byteorder='little')
			newB = (B + leftRotate(to_rotate, rotate_by[i])) & 0xFFFFFFFF
				
			A, B, C, D = D, newB, B, C
			# rotate the contents of the 4 MD buffers by one every pass through the loop

		# Add the final output of the above stage to initial buffer states
		for i, val in enumerate([A, B, C, D]):
			init_temp[i] += val
			init_temp[i] &= 0xFFFFFFFF
		# The init_temp list now holds the MD(in the form of the 4 buffers A, B, C, D) of the 512-bit block of the message fed.

	
	# The same process is to be performed for every 512-bit block to get the final MD(message digest).

	
	# Construct the final message from the final states of the MD Buffers
	return sum(buffer_content<<(32*i) for i, buffer_content in enumerate(init_temp))


def MD_to_hex(digest):
	# takes MD from the processing stage, change its endian-ness and return it as 128-bit hex hash
	raw = digest.to_bytes(16, byteorder='little')
	return '{:032x}'.format(int.from_bytes(raw, byteorder='big'))


def md5(msg):
	msg = bytearray(msg, 'ascii') # create a copy of the original message in form of a sequence of integers [0, 256)
	msg = pad(msg)
	processed_msg = processMessage(msg)
	# processed_msg contains the integer value of the hash
	message_hash = MD_to_hex(processed_msg)
	return message_hash




#Implementation
#alphabit = string.ascii_lowercase
alphabit = " abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
def calculate(msg):
    plain_text = msg #I love UOT IRAQ
    key = "malikabdulahslow"
    padded_msg = Buffer(plain_text)
    ECP =Vigenere_Encryption(padded_msg, key) 
    TTA=Text_to_ASCII(ECP)
    ATB=ASCII_to_Binary(TTA) 
    BTH=Binary_to_Hexa(ATB)       
    State=Block_to_State(BTH)
    XORed_bin_State=AddRoundKey(State)
    SubByte_State = SubByte(XORed_bin_State)
    Shifted_State=Shift_Rows(SubByte_State)
    state = [int(x, 16) for x in Shifted_State]
    mixed_state = mix_columns(state)
    output_hex = [format(x, '02x') for x in mixed_state]
    Enc_msg_Binary = Hexa_to_Binary(output_hex)
    Enc_msg_ASCII = binary_to_ascii(Enc_msg_Binary)
    return Enc_msg_ASCII

def hmd5():
    Hash_phrase = "Milky Way"
    MD5_Hash = md5(Hash_phrase)
    return MD5_Hash

def cal_dec(output_hex):
    key = "malikabdulahslow"
    state = [ord(char) for char in output_hex]
    decrypted_state = inv_mix_columns(state)
    output_hexx = [format(x, '02x') for x in decrypted_state]
    inv_Shifted_State=inv_shift_rows(output_hexx)
    inv_SubByte_State = inv_sub_bytes(inv_Shifted_State)
    inv_Addround_Key_bin=inv_AddRoundKey(inv_SubByte_State)
    inv_Addround_Key = Binary_to_Hexa(inv_Addround_Key_bin)
    State=inv_Block_to_State(inv_Addround_Key)
    inv_Flat_State = [item for sublist in State for item in sublist] 
    inv_Hexa_Binary = Hexa_to_Binary(inv_Flat_State)
    inv_ascii = (binary_to_ascii(inv_Hexa_Binary))
    vigenere_decdec= Vigenere_Decryption(inv_ascii, key)
    vigenere_decdec = vigenere_decdec.replace('z', '')
    return vigenere_decdec



HOST = '127.0.0.1'
PORT = 12345

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
print('Connected to Bravo!')
while True:
    message = input('Alpha > ')
    print(f'Encrypting "{message}"')
    print('Processing...')
    message = calculate(message)
    HASH = hmd5()
    message = message + HASH
    print(f'Encryption is done, sending "{message}')
    client_socket.sendall(message.encode())

    data = client_socket.recv(1024).decode()
    print('Message received...')
    print('Proceeding with Validating the integrity of the message...')
    hash_val = data[16:]
    print(f'Processing: {hash_val}')
    HASH = hmd5()
    if hash_val == HASH:
         print("Integrity of message was not compromised!")
         print("Proceeding with Decrypting the message...")
         dec_msg = cal_dec(data[:16])
         print(f"Bravo's Original Message: {dec_msg}")
    else:
         print("The integrity of the message has been compromised!!!")
         print("Message will NOT be decrypted!")
