#!/usr/bin/python3
# _*_ coding: utf-8 _*_
#
# Copyright (C) . All Rights Reserved
#
# @Time    : 2024/9/23 20:04
# @Author  : Tadcx1024
# @File    : main.py
# @IDE     : PyCharm

### PROCESS BASED ON HTTPS ###

import os
import random
from binascii import b2a_hex, a2b_hex
from tkinter import *
from tkinter import messagebox
import rsa
from Crypto.Cipher import AES

'''
Crypto报错处理
方法1 (可用)
pip install pycryptodome
pip install crypto
pip install pycrypto
然后去报错文件夹\AppData\Local\Programs\Python\Python311\Lib\site-packages 小写crypto改大写Crypto
from Crypto.Cipher import AES仍然红线不用理会，可以成功运行

方法2 (未测试)
pip uninstall crypto
pip uninstall pycryptodome
pip install pycryptodome
'''


def A生成秘钥并保存():
    pubkey, privkey = rsa.newkeys(4096, poolsize=16)  # 密钥长度128 256 512 1024 2048 3072 4096    poolsize=核心数

    # print(pubkey)
    rsa_pem_public_key = pubkey.save_pkcs1()
    rsa_der_public_key = pubkey.save_pkcs1("DER")
    print(rsa_pem_public_key.decode("utf-8"))
    # print(rsa_der_public_key)
    file = open("public.pem", 'wb')
    file.write(rsa_pem_public_key)
    file.close()

    # print(privkey)
    rsa_pem_priv_key = privkey.save_pkcs1()
    rsa_der_priv_key = privkey.save_pkcs1("DER")
    print(rsa_pem_priv_key.decode("utf-8"))
    # print(rsa_der_priv_key)
    file = open("private.pem", 'wb')
    file.write(rsa_pem_priv_key)
    file.close()
    print("           #############################")
    print("           ### 请将 public.pem 发送给B ###")
    print("           #############################\n")
    messagebox.showinfo("请将 public.pem 发送给B", "请将 public.pem 发送给B")


def B生成会话密钥并用A公钥加密():
    会话密钥 = random.randint(10000000000000000000000000000000, 99999999999999999999999999999999)  # 16位/32位
    print("会话密钥", 会话密钥, "长度", len(str(会话密钥)), "\n")
    # print(len(str(10000000000000000000000000000000))) #密钥长度测试
    file = open('会话密钥.pem', mode='w')  # 会话密钥写入文件
    file.write(str(会话密钥))
    file.close()

    with open('public.pem', mode='rb') as publicfile:  # 加载公钥
        keydata2 = publicfile.read()
    pubkey = rsa.PublicKey.load_pkcs1(keydata2)
    # print("公钥", pubkey)
    utf8_bytes = str(会话密钥).encode('utf8')
    已加密会话密钥 = rsa.encrypt(utf8_bytes, pubkey)
    file = open('已加密会话密钥.pem', mode='wb')  # 已加密会话密钥写入文件
    file.write(已加密会话密钥)
    file.close()
    会话密钥输入框.delete(0, last=len(会话密钥输入框.get()))  # 自动填充到输入框
    会话密钥输入框.insert(0, 会话密钥)  # 位置 插入值
    print("会话密钥已加密 长度", len(str(已加密会话密钥)), 已加密会话密钥)
    print("           ###################################")
    print("           ### 请将 已加密会话密钥.pem 发送给A ###")
    print("           ###################################\n")
    messagebox.showinfo("请将 已加密会话密钥.pem 发送给A", "请将 已加密会话密钥.pem 发送给A")
    # return 已加密会话密钥


def A收到加密会话密钥用私钥解密():
    with open('private.pem', mode='rb') as privatefile:  # 加载私钥
        keydata1 = privatefile.read()
    privkey = rsa.PrivateKey.load_pkcs1(keydata1)
    print("用私钥进行解密", privkey)
    with open('已加密会话密钥.pem', mode='rb') as encryfile:  # 加载加密会话密钥
        已加密会话密钥 = encryfile.read()
    解密会话密钥 = rsa.decrypt(已加密会话密钥, privkey)
    print("解密会话密钥", 解密会话密钥)
    file = open('会话密钥.pem', mode='wb')  # 解密会话密钥写入文件
    file.write(解密会话密钥)
    file.close()
    会话密钥输入框.delete(0, last=len(会话密钥输入框.get()))  # 自动填充到输入框
    会话密钥输入框.insert(0, 解密会话密钥)  # 位置 插入值


def add_to_16(text): # 如果待加密数据不足16位的倍数就用空格补足16位
    if len(text.encode('utf-8')) % 16:
        add = 16 - (len(text.encode('utf-8')) % 16)
    else:
        add = 0
    text = text + ('\0' * add)
    return text.encode('utf-8')



def AES加密():
    加密内容 = 加密内容输入框.get(1.0, END)
    加密内容 = 加密内容.rstrip("\n")  # 读取去除自带的末尾换行符/n
    print(加密内容)
    加密内容 = add_to_16(加密内容)  # AES需要补全为16倍数
    会话密钥 = 会话密钥输入框.get()
    iv=(会话密钥[0:32:2]).encode()  # 根据随机会话密钥切片出16位的iv偏移量
    #print(iv,len(iv))
    aes = AES.new(会话密钥.encode('utf-8'), AES.MODE_CBC, iv)  # key(32位会话密钥充当) mode iv偏移量(16位)
    print('加密内容:', 加密内容)
    加密后的字节码 = aes.encrypt(加密内容)  # 加密
    # print(type(加密后的字节码))
    加密后的字节码 = b2a_hex(加密后的字节码)  # 二进制数据(bytes)转16进制字符串(bytes)在文本框显示 防乱码
    # print(type(加密后的字节码))
    print('加密后的字节码：', 加密后的字节码, "\n")

    解密内容输入框.delete(1.0, END)  # 清空文本区
    解密内容输入框.insert('10.end', 加密后的字节码)


def AES解密():
    解密前内容 = 解密内容输入框.get(1.0, END)
    解密前内容 = 解密前内容.rstrip("\n")  # 读取去除自带的末尾换行符/n
    会话密钥 = 会话密钥输入框.get()
    # print(解密前内容)
    # print(type(解密前内容))
    解密前内容 = 解密前内容.encode('utf-8')  # 文本框读取的数据类型为str，转回原本的16进制字符串(bytes)
    # print(解密前内容)
    # print(type(解密前内容))
    解密前内容 = a2b_hex(解密前内容)  # 16进制字符串(bytes)再转回最初的二进制数据(bytes)
    iv = (会话密钥[0:32:2]).encode()  # 根据随机会话密钥切片出16位的iv偏移量
    aes = AES.new(会话密钥.encode('utf-8'), AES.MODE_CBC, iv)  # key(32位会话密钥充当，32位字符串=256位秘钥，16位字符串=128位秘钥，24位字符串=192位秘钥) mode iv偏移量(16位)
    解密后内容 = aes.decrypt(解密前内容)  # 解密
    解密后内容 = bytes.decode(解密后内容).rstrip('\0')  # 去除 加密时末尾为了补足16倍而添加的\0

    print('解密前内容：', 解密前内容, )
    print('解密后内容：', 解密后内容, "\n")
    加密内容输入框.delete(1.0, END)  # 清空文本区
    加密内容输入框.insert('10.end', 解密后内容)


if __name__ == '__main__':  # 主进程:界面

    # 创建一个主窗口
    top = Tk()
    # 设置窗口标题
    top.title("Encryption      *PROCESS BASED ON HTTPS* ")
    # 创建一个标签，并设置其文本内容为"Hello, World!"

    说明1 = Label(top, text="通信双方事先明确谁担任A 谁担任B", fg="red")
    说明1.pack()  # 将标签添加到窗口中

    A生成秘钥并保存Button = Button(top, text="1.  A生成公/私秘钥，私钥保留，公钥发给B", command=A生成秘钥并保存)
    A生成秘钥并保存Button.pack()

    B生成会话密钥并用A公钥加密Button = Button(top, text="2.  B生成会话密钥，使用A的公钥加密，加密后会话密钥发给A",
                                              command=B生成会话密钥并用A公钥加密)
    B生成会话密钥并用A公钥加密Button.pack()
    A收到加密会话密钥用私钥解密Button = Button(top, text="3.  A收到加密会话密钥，使用自己私钥解密，获得明文会话密钥",
                                               command=A收到加密会话密钥用私钥解密)
    A收到加密会话密钥用私钥解密Button.pack()

    说明3 = Label(top, text="4~∞ 此后双向通信只需要根据会话密钥进行加解密即可\n")
    说明3.pack()
    说明4 = Label(top, text="双方会话密钥一致才可正常加解密，如需要交换同步新的会话密钥请重新执行1-3步", fg="blue")
    说明4.pack()  # 将标签添加到窗口中
    说明2 = Label(top, text="私钥 与 明文会话密钥 严禁外传", fg="red")
    说明2.pack()  # 将标签添加到窗口中

    会话密钥输入框 = Entry(top, bd=5, width=32)
    会话密钥输入框.pack()
    会话密钥说明 = Label(top, text=" ↑ 会话密钥 ↑ ")
    会话密钥说明.pack()  # 将标签添加到窗口中
    if os.path.exists("会话密钥.pem"):
        with open('会话密钥.pem', mode='r') as 会话密钥file:  # 加载会话密钥
            会话密钥 = 会话密钥file.read()
        会话密钥输入框.delete(0, last=len(会话密钥输入框.get()))  # 自动填充到输入框
        会话密钥输入框.insert(0, 会话密钥)  # 位置 插入值

    加密内容输入框 = Text(top, bd=5, width=50, height=10)
    加密内容输入框.pack()
    加密Button = Button(top, text="加密内容 ↓", command=AES加密)
    加密Button.place(x=125, y=370)  # 按钮可调位置
    解密Button = Button(top, text="解密内容 ↑", command=AES解密)
    解密Button.place(x=250, y=370)
    解密内容输入框 = Text(top, bd=5, width=50, height=10)
    解密内容输入框.pack()

    # 运行主循环，等待用户交互
    top.mainloop()
