import glob

file_bin = glob.glob('*.bin')

for file in file_bin:
    # Read the binary file
    with open(file, 'rb') as f_in:
        byte_data = f_in.read()

    # Convert the byte data to a binary string
    binary_string = ''.join(format(byte, '08b') for byte in byte_data)

    name = file.split('.')[0]  # Get the name of the file without extension

    # Write the binary string to a text file
    with open(name + '.txt', 'w') as f_out:
        f_out.write(binary_string)
