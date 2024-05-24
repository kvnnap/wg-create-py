import json

def load_json(file_name):
    with open(file_name, 'r') as fp:
        return json.load(fp)
    
def write_to_file(file_path, content):
    with open(file_path, 'w') as file:
        file.write(content)

def read_from_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def replace_tokens_in_string(content, token_map):
    for token, mapped_value in token_map.items():
        content = content.replace(token, str(mapped_value))
    return content

def replace_tokens_in_file(template_file_path, file_path, token_map):
    # Read the content of the file
    content = read_from_file(template_file_path)

    # Replace tokens with mapped values
    content = replace_tokens_in_string(content, token_map)

    # Write the modified content back to the file
    write_to_file(file_path, content)
