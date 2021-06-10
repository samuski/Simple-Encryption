# Created by Samuski Kwon
#
# Simple GUI and encrypt/decrypt mechanism


import binascii
from tkinter import *
from tkinter import messagebox
from tkinter.filedialog import *


def count(binary):
    count = 0
    for x in range(len(binary)):
        if binary[x] == 1:
            count += 1
    return count


def keygen(key, length):
    keystring = []
    temp = []
    output = []

    for i in key:
        keystring.append(int(i))

    list1 = keystring
    list2 = keystring[::2] + keystring[1::2]
    list3 = keystring[3::4] + keystring[2::4] + keystring[1::4] + keystring[::4]

    for i in range(length):
        val = list1[i]
        list1.append(list1[i])
        list2.append(list2[i])
        list3.append(list3[i])
        temp += str(val)

    for i in temp:
        output.append(str(i))

    return output


def encrypt(text, encoding='utf-8', errors='surrogatepass'):
    bits = bin(int(binascii.hexlify(text.encode(encoding, errors)), 16))[2:]
    return bits.zfill(8 * ((len(bits) + 7) // 8))


def decrypt(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return int2bytes(n).decode(encoding, errors)


def int2bytes(i):
    hex_string = '%x' % i
    n = len(hex_string)
    return binascii.unhexlify(hex_string.zfill(n + (n & 1)))


def add_key(binary, key):
    b = list(binary)
    for x in range(len(binary)-1):
        if b[x] == key[x] == '1':
            b[x] = '0'
        elif b[x] != key[x]:
            b[x] = '1'
    return "".join(b)


def crypto(input_text, input_pass):
    binary = encrypt(input_text)
    key = keygen(encrypt(input_pass), len(binary))
    binary = add_key(binary, key)
    output_text = decrypt(binary)
    return output_text


def pop_up(string):
    messagebox.showinfo("Output", string)


def select_file():
    filename = askopenfilename(parent = window, filetypes=("txt file", "*.txt"))
    text_file = open(filename, "r")
    text = text_file.readlines()


def run():
    text_input = text_entry.get()
    pass_input = pass_entry.get()
    if text_input is '' or pass_input is '':
        return
    text_entry.delete(0, END)
    pass_entry.delete(0, END)
    result_entry.delete(0, END)
    string = crypto(text_input, pass_input)
    result_entry.insert(INSERT, string)


def GUI():
    global window
    window = Tk()

    global text_entry
    global pass_entry
    global result_entry

    window.title("Cryptonator")
    window.geometry("400x200+400+200")
    window.resizable(width=FALSE, height=FALSE)

    plaintext = Label(window, text="Plaintext", font="arial 14")
    passcode = Label(window, text="Passcode ", font="arial 14")
    result = Label(window, text="Result", font="arial 14")
    plaintext.grid(row=0, column=0)
    passcode.grid(row=1, column=0)
    result.grid(row=2, column=0)

    text_entry = Entry(window, bg='white', width=40)
    pass_entry = Entry(window, bg='white', width=40)
    result_entry = Entry(window, bg='white', width=40)

    text_entry.grid(row=0, column=1)
    pass_entry.grid(row=1, column=1)
    result_entry.grid(row=2, column=1)

    #open_file = Button(window, text="Open", command=select_file)
    execute = Button(window, text="Convert", command=run)
    execute.grid(row=3, column=1)

    window.mainloop()


GUI()