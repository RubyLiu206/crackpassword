#python file deal with the decryption and encryption in SearchPW.py
#files with the encryption information in : formsring.txt, SHA1.txt, password.file
#files with the decryption information in : Formsring_output.txt, Linkedin_output.txt, Yahoo_output.file
#import hashlib for hax and formal information

import hashlib


def search_linkedin_pwd(raw_file, output_file, password_file):
    max_cnt = 100

    # Deal with the raw file
    raw_data_hash = construct_hash(raw_file)

    # Final message will save in output file
    # Use the useful password
    with open(output_file, 'w') as output_write:
        # SHA1
        with open(password_file, 'r') as useful_password:
            for line in useful_password.readlines():
                line = line.strip()
                line = line.replace('\n', '')
                hash_code = hashlib.sha1(line.encode('utf-8')).hexdigest()
                if hash_code in raw_data_hash:
                    output_write.write(hash_code + ' ' + line + '\n')
                    max_cnt -= 1
                    if max_cnt == 0:
                        break
        # SHA1 begin with 00000
        if max_cnt != 0:
            with open(password_file, mode='r') as freq_reader_handler:
                for line in freq_reader_handler.readlines():
                    line = line.strip()
                    line = line.replace('\n', '')
                    hash_code = hashlib.sha1(line.encode('utf-8')).hexdigest()
                    hash_code_cracked = '00000' + hash_code[5:]
                    if hash_code_cracked in raw_data_hash:
                        output_write.write(hash_code_cracked + ' ' + line + '\n')
                        max_cnt -= 1
                        if max_cnt == 0:
                            break
    print("linkedin finish")
                

def search_formspring_pwd(raw_file, output_file, password_file):
    max_cnt = 100
    # Deal with the raw file into hash
    raw_data_hashmap = construct_hash(raw_file)
    with open(output_file, 'w') as output_write:
        with open(password_file, 'r') as useful_password:
            for line in useful_password.readlines():
                line = line.strip()
                line = line.replace('\n', '')
                salt_front_lst = [str(i + 10 * j) + line for i in range(10) for j in range(10)]
                salt_end_lst = [line + str(i + 10 * j) for i in range(10) for j in range(10)]
                salt_lst = salt_front_lst + salt_end_lst
                for salt_plain_text in salt_lst:
                    hash_code = hashlib.sha256(salt_plain_text.encode('utf-8')).hexdigest()
                    if hash_code in raw_data_hashmap:
                        output_write.write(hash_code + ' ' + line + '\n')
                        max_cnt -= 1
                        if max_cnt == 0:
                            break
                if max_cnt == 0:
                    break
    print("formspring finish")


def search_yahoo_pwd(raw_file, output_file):
    start_write = False
    cnt = 100

    with open(raw_file, 'r') as reader_handler:
        with open(output_file, 'w') as writer_handler:
            for line in reader_handler.readlines():
                if start_write:
                    if line.strip() == '':
                        continue
                    _, _, pwd = line.split(':')
                    writer_handler.write(line.replace('\n', '') + ' ' + pwd)
                    cnt -= 1
                    if cnt == 0:
                        break

                if 'user_id' in line and 'user_name' in line and 'clear_passwd' in line and 'passwd' in line:
                    start_write = True
    print("Yahoo finish" )


def construct_hash(raw_file_path):
    hashmap = set()
    with open(raw_file_path, 'r') as reader_handler:
        for line in reader_handler.readlines():
            line = line.strip()
            line = line.replace('\n', '')
            if line == '':
                continue
            hashmap.add(line)
    return hashmap


password = ["Useful_PW.txt"]
yahoo = ["password.txt", "Yahoo_output.txt"]
linkedin = ["SHA1.txt", "Linkedin_output.txt"]
formspring = ["formspring.txt", "Formspring_output.txt"]
search_linkedin_pwd(linkedin[0],linkedin[1],password[0])
search_formspring_pwd(formspring[0],formspring[1],password[0])
search_yahoo_pwd(yahoo[0],yahoo[1])



