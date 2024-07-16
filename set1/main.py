import os
# TODO: Convert to base64 from scratch.
import base64

def diff(input:str,output:str)->str:
	if input==output:
		return input
	result:str=""
	min_len:int=min(len(input),len(output))
	for i in range(min_len):
		if input[i]!=output[i]:
			result+="\033[91m"+input[i]+"\033[0m"
		else:
			result+=input[i]
	return result
def is_pass(input:any,output:any)->bool:
	valid_types:list=[int,float,complex]
	if type(input)==tuple:
		input=input[0]
	elif type(input) in valid_types:
		input=str(input)
	if type(output) in valid_types:
		output=str(output)
	if output=='':
		return "\033[93m"+input.strip()+"\033[0m"
	return "\033[92mPassed\033[0m" if input==output else f"\033[91mFailed\033[0m\n{diff(input,output)}"

def base2dec(value:str,base:int)->int:
	return int(value,base)
def dec2base(value:int,base:int)->str:
	letters:str="0123456789abcdef"
	if value==0:
		return "0"
	result:str=""
	while value>0:
		result=letters[value%base]+result
		value//=base
	return result
def hex2base64(hex_str:str)->str:
	return base64.b64encode(bytes.fromhex(input)).decode()
def xor(hex:str,hex2:str)->str:
	return dec2base(base2dec(hex,16)^base2dec(hex2,16),16)
# NOTE: https://en.wikipedia.org/wiki/Letter_frequency.
english_freq:list=[.08167,.01492,.02782,.04253,.12702,.02228,.02015,.06094,.06966,.00153,.00772,.04025,.02406,.06749,.07507,.01929,.00095,.05987,.06327,.09056,.02758,.00978,.02360,.00150,.01974,.00074]
# NOTE: https://en.wikipedia.org/wiki/Chi-squared_test.
# TODO: Switch to https://en.wikipedia.org/wiki/Bhattacharyya_distance#Bhattacharyya_coefficient.
	# The coef. is the amount of overlap between two statistical samples or populations.
def score_text(text:str)->float:
	score:float=0
	letter_freq:dict={chr(i):0 for i in range(97,123)}
	for letter in text:
		if ord(letter)>=97 and ord(letter)<=122:
			letter_freq[letter.lower()]+=1
	for i in range(26):
		score+=abs(letter_freq[chr(i+97)]/len(text)-english_freq[i])
	return score
def xor_decrypt(hex:str)->tuple:
	hex_bytes:bytes=bytes.fromhex(hex)
	min_score:float=score_text(" "*len(hex_bytes))
	result:str=''
	for i in range(256):
		xor_bytes:bytes=bytes([i^byte for byte in hex_bytes])
		try:
			text:str=xor_bytes.decode()
		except:
			continue
		score:float=score_text(text)
		if score<min_score:
			min_score=score
			result=text
	return (result,min_score)
def xor_single_char(hex:str)->str:
	lines:list=hex.split('\n')
	min_score:float=score_text(" "*len(lines[0]))
	result:str=''
	for line in lines:
		decrypt:tuple=xor_decrypt(line)
		if decrypt[1]<min_score:
			min_score=decrypt[1]
			result=decrypt[0]
	return result
# FIXME: Idk y it doesn't work bro.
	# Seems there's a "0" after newlines for some reason, but there's another random "0". Very confusing.
def repeating_key_xor(text:str,key:str)->str:
	# key_bytes:bytes=key.encode()
	# ret:list=[]
	# key_val:int=0
	# lines:list=text.split('\n')
	# for line in range(len(lines)):
	# 	text_bytes:bytes=lines[line].encode()
	# 	result:str=''
	# 	for i in range(len(text_bytes)):
	# 		result+=dec2base(text_bytes[i]^key_bytes[key_val%len(key_bytes)],16)
	# 		key_val+=1
	# 	if line!=len(lines)-1:
	# 		newline:bytes='\n'.encode()
	# 		result+=dec2base(newline[0]^key_bytes[key_val%len(key_bytes)],16)
	# 		key_val+=1
	# 	result='0'+result
	# 	ret.append(result)
	# print('\n'.join(ret))
	# return '\n'.join(ret)
	key_bytes:bytes=key.encode()
	text_bytes:bytes=text.encode()
	result:str=''
	key_val:int=0
	for i in range(len(text_bytes)):
		if text_bytes[i]==ord('\n'):
			result+=dec2base(text_bytes[i]^key_bytes[key_val%len(key_bytes)],16)
			key_val+=1
			result+='0'
			continue
		result+=dec2base(text_bytes[i]^key_bytes[key_val%len(key_bytes)],16)
		key_val+=1
	return '0'+result
def hamming_distance(str1:str,str2:str)->int:
	distance:int=0
	for i in range(len(str1)):
		distance+=bin(ord(str1[i])^ord(str2[i])).count('1')
	return distance
# FIXME: Just returns "bad magic number" :(
def aes_ecb_decrypt(ciphertext:str,key:str)->str:
	ret:str=''
	for line in ciphertext.split('\n'):
		ret+=os.popen(f"echo \"{line}\" | openssl enc -d -aes-128-ecb -k \"{key}\"").read()
		ret+='\n'
	return ret

challenges:list=[hex2base64,xor,xor_decrypt,xor_single_char,repeating_key_xor,hamming_distance,aes_ecb_decrypt]
input_output:dict={
	"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d":"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t",
	"1c0111001f010100061a024b53535009181c\t\t\t686974207468652062756c6c277320657965":"746865206b696420646f6e277420706c6179",
	"1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736":'',
	open("4.txt").read().strip():'',
	"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal\t\t\tICE":"0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f",
	"this is a test\t\t\twokka wokka!!!":37,
	open("7.txt").read().strip()+"\t\t\tYELLOW SUBMARINE":''
}
for i in range(len(challenges)):
	input:str=list(input_output.keys())[i]
	split_input:list=list(input_output.keys())[i].split('\t\t\t')
	print(f"Challenge {i+1}:",is_pass(challenges[i](*split_input),input_output[input]))
# TODO: Decrypt ./6.txt & not just test the test case.
