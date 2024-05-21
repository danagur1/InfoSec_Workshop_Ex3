import os

C_CODE_PATH = "data/code"

ENGLISH_TEXT_PATH = "data/texts"

C = 10000

def get_c_code_examples():
    file_texts = []
    for filename in os.listdir(C_CODE_PATH):
        if filename.endswith(".c"):
            file_path = os.path.join(C_CODE_PATH, filename)
            with open(file_path, 'r') as file:
                file_texts.append(file.read())
    return file_texts

def get_english_text_examples():
    file_texts = []
    for filename in os.listdir(ENGLISH_TEXT_PATH):
        if filename.endswith(".txt"):
            file_path = os.path.join(ENGLISH_TEXT_PATH, filename)
            with open(file_path, 'r') as file:
                file_texts.append(file.read())
    return file_texts

def calculate_word_variety(text):
    words = text.split()
    # Use regex to find all words
    total_len = len(words)
    # Use a set to find unique words
    unique_words_len = len(set(words))
    # Return the number of unique words
    return unique_words_len/total_len

def count_list_words(text, list_words):
    return max([text.count(word) for word in list_words])

def calculate_words(text):
    loop_words = ["while(", "while (", "for(", "for ("]
    condition_words = ["if(", "if ("]
    notes = ["//", "/*"]
    code_strings = [";", "{", "void ", "&", "int ", "_"]
    return C*(min(count_list_words(text, loop_words), count_list_words(text, condition_words), 
    count_list_words(text, notes), count_list_words(text, code_strings))/len(text))

def calculate_avg_words(texts_list):
    return sum([calculate_words(text) for text in texts_list])/len(texts_list)

def calculate_avg_variety(texts_list):
    return sum([calculate_word_variety(text) for text in texts_list])/len(texts_list)

def accept_packet(data):
    examples_english_texts = get_english_text_examples()
    examples_c_code = get_c_code_examples()
    data_variety = calculate_word_variety(data.decode())
    if abs(calculate_avg_variety(examples_english_texts)-data_variety)<abs(calculate_avg_variety(examples_c_code)-data_variety):
        if abs(calculate_avg_words(examples_english_texts)-data_variety)<abs(calculate_avg_words(examples_c_code)-data_variety):
        return False
    return True